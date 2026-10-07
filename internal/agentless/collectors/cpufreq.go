package collectors

import (
	"bytes"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	Register(Registration{Name: "cpufreq", OS: "linux", DefaultEnabled: true, Factory: newCpufreqCollector})
}

var cpufreqNumbers = [...]struct{ attribute, family, help string }{
	{"cpuinfo_cur_freq", "frequency_hertz", "Current CPU thread frequency in hertz."},
	{"cpuinfo_min_freq", "frequency_min_hertz", "Minimum CPU thread frequency in hertz."},
	{"cpuinfo_max_freq", "frequency_max_hertz", "Maximum CPU thread frequency in hertz."},
	{"scaling_cur_freq", "scaling_frequency_hertz", "Current scaled CPU thread frequency in hertz."},
	{"scaling_min_freq", "scaling_frequency_min_hertz", "Minimum scaled CPU thread frequency in hertz."},
	{"scaling_max_freq", "scaling_frequency_max_hertz", "Maximum scaled CPU thread frequency in hertz."},
}
var cpufreqStrings = [...]string{"scaling_governor", "scaling_available_governors"}

const cpufreqAttributes = len(cpufreqNumbers) + len(cpufreqStrings)

type cpufreqCollector struct {
	numbers  [len(cpufreqNumbers)]*prometheus.Desc
	governor *prometheus.Desc
}

var _ agentless.Expander = (*cpufreqCollector)(nil)

func newCpufreqCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	c := &cpufreqCollector{governor: prometheus.NewDesc(agentless.Namespace+"_cpu_scaling_governor", "Current enabled CPU frequency governor.", []string{"cpu", "governor"}, nil)}
	for i, spec := range cpufreqNumbers {
		c.numbers[i] = prometheus.NewDesc(agentless.Namespace+"_cpu_"+spec.family, spec.help, []string{"cpu"}, nil)
	}
	return c, nil
}
func (*cpufreqCollector) Name() string { return "cpufreq" }
func (*cpufreqCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.CommandRead("ls", "-1", "/sys/devices/system/cpu")}
}
func cpufreqRead(cpu, attribute string) agentless.Read {
	return agentless.FileRead("/sys/devices/system/cpu/" + cpu + "/cpufreq/" + attribute)
}

// Bound all listing rows before retaining names, including unrelated sysfs
// entries. Eight fixed attributes permit at most 32 CPUs under the read cap.
func (c *cpufreqCollector) cpus(in agentless.Input) ([]string, error) {
	read := c.Reads()[0]
	r := in[read.ID]
	if r.NotExist && !r.TimedOut && !r.Truncated {
		return nil, nil
	}
	output, err := in.Output(read)
	if err != nil {
		return nil, err
	}
	if len(output) == 0 {
		return nil, nil
	}
	if output[len(output)-1] != '\n' {
		return nil, fmt.Errorf("cpufreq: unterminated listing")
	}
	var cpus []string
	rows := 0
	for row := range bytes.SplitSeq(output[:len(output)-1], []byte{'\n'}) {
		rows++
		if rows > agentless.MaxExpandedReads || len(row) > 64 {
			return nil, fmt.Errorf("cpufreq: listing limit exceeded")
		}
		if len(row) == 0 {
			return nil, fmt.Errorf("cpufreq: empty listing row")
		}
		if !bytes.HasPrefix(row, []byte("cpu")) || len(row) == 3 {
			continue
		}
		valid := true
		for _, b := range row[3:] {
			if b < '0' || b > '9' {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		cpu := string(row)
		if err := cpufreqRead(cpu, "cpuinfo_cur_freq").Validate(); err != nil {
			return nil, err
		}
		for _, previous := range cpus {
			if previous == cpu {
				return nil, fmt.Errorf("cpufreq: duplicate CPU")
			}
		}
		if (len(cpus)+1)*cpufreqAttributes > agentless.MaxExpandedReads {
			return nil, fmt.Errorf("cpufreq: expanded read limit exceeded")
		}
		cpus = append(cpus, cpu)
	}
	return cpus, nil
}
func (c *cpufreqCollector) Expand(_ agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	cpus, err := c.cpus(in)
	if err != nil {
		return nil, err
	}
	reads := make([]agentless.Read, 0, len(cpus)*cpufreqAttributes)
	for _, cpu := range cpus {
		for _, spec := range cpufreqNumbers {
			read := cpufreqRead(cpu, spec.attribute)
			if err := read.Validate(); err != nil {
				return nil, err
			}
			reads = append(reads, read)
		}
		for _, attribute := range cpufreqStrings {
			read := cpufreqRead(cpu, attribute)
			if err := read.Validate(); err != nil {
				return nil, err
			}
			reads = append(reads, read)
		}
	}
	return reads, nil
}

func cpufreqOutput(in agentless.Input, read agentless.Read) ([]byte, error) {
	if err := read.Validate(); err != nil {
		return nil, err
	}
	r := in[read.ID]
	if r.NotExist && !r.TimedOut && !r.Truncated {
		return nil, nil
	}
	return in.Output(read)
}

func (c *cpufreqCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	cpus, err := c.cpus(in)
	if err != nil {
		return err
	}
	var metrics []prometheus.Metric
	for _, cpu := range cpus {
		label := strings.TrimPrefix(cpu, "cpu")
		for i, spec := range cpufreqNumbers {
			output, err := cpufreqOutput(in, cpufreqRead(cpu, spec.attribute))
			if err != nil {
				return err
			}
			// Malformed attributes are isolated; bound before converting to strings.
			if len(output) > 32 {
				continue
			}
			raw := bytes.TrimSpace(output)
			value, err := strconv.ParseUint(string(raw), 10, 64)
			if err != nil {
				continue
			}
			metrics = append(metrics, targetMetric(c.numbers[i], prometheus.GaugeValue, float64(value)*1000, label))
		}
		current, err := cpufreqOutput(in, cpufreqRead(cpu, cpufreqStrings[0]))
		if err != nil {
			return err
		}
		available, err := cpufreqOutput(in, cpufreqRead(cpu, cpufreqStrings[1]))
		if err != nil {
			return err
		}
		// At most 32 governors, each at most 64 bytes: at most 1216 series
		// across the 32 CPUs, with bounded labels and no unbounded token slice.
		if len(current) > 65 || len(available) > 32*65 || !utf8.Valid(current) || !utf8.Valid(available) {
			continue
		}
		governor := string(bytes.TrimSpace(current))
		if governor == "" || len(governor) > 64 || strings.ContainsAny(governor, " \t\r\n") {
			continue
		}
		var governors []string
		valid := true
		for token := range strings.SplitSeq(string(bytes.TrimSpace(available)), " ") {
			if len(token) == 0 || len(token) > 64 || strings.ContainsAny(token, "\t\r\n") || len(governors) == 32 {
				valid = false
				break
			}
			for _, previous := range governors {
				if previous == token {
					valid = false
					break
				}
			}
			if !valid {
				break
			}
			governors = append(governors, token)
		}
		if !valid {
			continue
		}
		for _, g := range governors {
			value := 0.0
			if g == governor {
				value = 1
			}
			metrics = append(metrics, targetMetric(c.governor, prometheus.GaugeValue, value, label, g))
		}
	}
	for _, metric := range metrics {
		ch <- metric
	}
	return nil
}
