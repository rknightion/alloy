package collectors

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
)

func init() {
	Register(Registration{Name: "stat", OS: "linux", DefaultEnabled: true, Factory: newStatCollector})
}

type statCollector struct{}

func newStatCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &statCollector{}, nil
}

// Name implements agentless.Collector.
func (c *statCollector) Name() string { return "stat" }

// Reads implements agentless.Collector.
func (c *statCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/stat")}
}

var statMetrics = []struct {
	key, name, help string
	kind            prometheus.ValueType
}{
	{"intr", "intr_total", "Total number of interrupts serviced.", prometheus.CounterValue},
	{"ctxt", "context_switches_total", "Total number of context switches.", prometheus.CounterValue},
	{"processes", "forks_total", "Total number of forks.", prometheus.CounterValue},
	{"btime", "boot_time_seconds", "Node boot time, in unixtime.", prometheus.GaugeValue},
	{"procs_running", "procs_running", "Number of processes in runnable state.", prometheus.GaugeValue},
	{"procs_blocked", "procs_blocked", "Number of processes blocked waiting for I/O to complete.", prometheus.GaugeValue},
}

// Update implements agentless.Collector.
func (c *statCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	stats, err := readProcStat(in)
	if err != nil {
		return err
	}
	for _, m := range statMetrics {
		desc := prometheus.NewDesc(prometheus.BuildFQName(agentless.Namespace, "", m.name), m.help, nil, nil)
		ch <- prometheus.MustNewConstMetric(desc, m.kind, float64(stats.values[m.key]))
	}
	return nil
}

// Linux reports CPU time in USER_HZ, fixed at 100, independently of the
// kernel's scheduling tick frequency. Guest time is included in user/nice.
type cpuTimes [10]float64

type procStat struct {
	cpus   map[int64]cpuTimes
	values map[string]uint64
}

// readProcStat is shared because cpu and stat read the same batch section.
// Parse the complete section before emitting metrics or changing cached state.
func readProcStat(in agentless.Input) (procStat, error) {
	out, err := in.Output(agentless.FileRead("/proc/stat"))
	if err != nil {
		return procStat{}, err
	}
	stats := procStat{cpus: make(map[int64]cpuTimes), values: make(map[string]uint64)}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	// The interrupt line can be much larger than Scanner's default limit.
	scanner.Buffer(make([]byte, 8192), 1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		key := fields[0]
		isCPU := strings.HasPrefix(key, cpuSubsystem)
		known := isCPU || key == "softirq"
		for _, m := range statMetrics {
			known = known || key == m.key
		}
		if !known {
			continue
		}
		if len(fields) < 2 {
			return procStat{}, fmt.Errorf("/proc/stat: missing value for %s", key)
		}
		if isCPU {
			id := int64(-1)
			if key != cpuSubsystem {
				id, err = strconv.ParseInt(strings.TrimPrefix(key, cpuSubsystem), 10, 64)
				if err != nil || id < 0 {
					return procStat{}, fmt.Errorf("/proc/stat: invalid CPU ID %q", key)
				}
			}
			var times cpuTimes
			for i := 1; i < len(fields) && i <= len(times); i++ {
				value, err := strconv.ParseUint(fields[i], 10, 64)
				if err != nil {
					return procStat{}, fmt.Errorf("/proc/stat: %s: %w", key, err)
				}
				times[i-1] = float64(value) / 100
			}
			if id >= 0 {
				stats.cpus[id] = times
			}
			continue
		}
		count := 1
		if key == "intr" {
			count = len(fields) - 1
		}
		if key == "softirq" {
			count = 11
			if len(fields) < count+1 {
				return procStat{}, fmt.Errorf("/proc/stat: incomplete softirq line")
			}
		}
		for i := 1; i <= count; i++ {
			value, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				return procStat{}, fmt.Errorf("/proc/stat: %s: %w", key, err)
			}
			if i == 1 {
				stats.values[key] = value
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return procStat{}, fmt.Errorf("/proc/stat: %w", err)
	}
	return stats, nil
}
