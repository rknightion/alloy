package collectors

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	Register(Registration{Name: "selinux", OS: "linux", DefaultEnabled: true, Factory: newSELinuxCollector})
}

type selinuxCollector struct{ descs [3]*prometheus.Desc }

func newSELinuxCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	c := &selinuxCollector{}
	for i, spec := range [...]struct{ name, help string }{
		{"enabled", "SELinux is enabled, 1 is true, 0 is false"},
		{"config_mode", "Configured SELinux enforcement mode"},
		{"current_mode", "Current SELinux enforcement mode"},
	} {
		c.descs[i] = prometheus.NewDesc(agentless.Namespace+"_selinux_"+spec.name, spec.help, nil, nil)
	}
	return c, nil
}

func (*selinuxCollector) Name() string { return "selinux" }
func (*selinuxCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/self/mountinfo"), agentless.FileRead("/sys/fs/selinux/enforce"), agentless.FileRead("/etc/selinux/config")}
}

func (c *selinuxCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	reads := c.Reads()
	var outputs [3][]byte
	var missing [3]bool
	// Transport failures are errors even when another read says SELinux is absent.
	for i, read := range reads {
		result := in[read.ID]
		if result.NotExist && !result.TimedOut && !result.Truncated {
			missing[i] = true
			continue
		}
		output, err := in.Output(read)
		if err != nil {
			return err
		}
		outputs[i] = output
	}
	enabled := false
	if !missing[0] {
		var err error
		enabled, err = parseSELinuxMounts(outputs[0])
		if err != nil {
			return err
		}
	}
	if !enabled {
		ch <- targetMetric(c.descs[0], prometheus.GaugeValue, 0)
		return nil
	}
	config, current := -1, -1
	if !missing[2] {
		var err error
		config, err = parseSELinuxConfig(outputs[2])
		if err != nil {
			return err
		}
	}
	if !missing[1] {
		// Kernel enforce files contain one digit, with or without a final newline.
		if len(outputs[1]) > 16 {
			return fmt.Errorf("selinux: enforce too long")
		}
		switch string(bytes.TrimSpace(outputs[1])) {
		case "0":
			current = 0
		case "1":
			current = 1
		default:
			return fmt.Errorf("selinux: invalid enforce mode")
		}
	}
	for i, value := range [...]int{1, config, current} {
		ch <- targetMetric(c.descs[i], prometheus.GaugeValue, float64(value))
	}
	return nil
}

// Only three label-free families/series are retained. Bound source bytes,
// rows and tokens before any input-sized retention; no target strings escape.
// Mountinfo supplies the selinuxfs detection used by go-selinux, including its
// rejection of read-only mounts. Reads stay fixed even for nonstandard mounts.
func parseSELinuxMounts(output []byte) (bool, error) {
	if len(output) > 4*1024*1024 {
		return false, fmt.Errorf("selinux: mountinfo too large")
	}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	enabled, rows := false, 0
	for scanner.Scan() {
		rows++
		if rows > 20000 {
			return false, fmt.Errorf("selinux: too many mounts")
		}
		count, separator := 0, -1
		var options, fsType []byte
		for token := range bytes.FieldsSeq(scanner.Bytes()) {
			if len(token) > 4096 || count >= 256 {
				return false, fmt.Errorf("selinux: mount field limit")
			}
			if count == 5 {
				options = token
			}
			if separator < 0 && bytes.Equal(token, []byte("-")) {
				separator = count
			}
			if separator >= 0 && count == separator+1 {
				fsType = token
			}
			count++
		}
		if separator < 6 || count != separator+4 {
			return false, fmt.Errorf("selinux: malformed mountinfo")
		}
		if bytes.Equal(fsType, []byte("selinuxfs")) {
			for option := range bytes.SplitSeq(options, []byte(",")) {
				if bytes.Equal(option, []byte("rw")) {
					enabled = true
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("selinux: mount scan: %w", err)
	}
	if rows == 0 {
		return false, fmt.Errorf("selinux: empty mountinfo")
	}
	return enabled, nil
}

func parseSELinuxConfig(output []byte) (int, error) {
	if len(output) > 64*1024 {
		return 0, fmt.Errorf("selinux: config too large")
	}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 4096), 4096)
	mode, seen, rows := -1, false, 0
	for scanner.Scan() {
		rows++
		if rows > 1024 {
			return 0, fmt.Errorf("selinux: too many config rows")
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] == '#' || line[0] == ';' {
			continue
		}
		key, value, ok := bytes.Cut(line, []byte("="))
		if !ok || len(key) == 0 || len(value) == 0 {
			return 0, fmt.Errorf("selinux: malformed config")
		}
		if !bytes.Equal(key, []byte("SELINUX")) {
			continue
		}
		if seen {
			return 0, fmt.Errorf("selinux: duplicate mode")
		}
		seen = true
		switch string(bytes.Trim(value, `"`)) {
		case "enforcing":
			mode = 1
		case "permissive":
			mode = 0
		case "disabled":
			mode = -1
		default:
			return 0, fmt.Errorf("selinux: invalid config mode")
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("selinux: config scan: %w", err)
	}
	// go-selinux returns Disabled (-1) when SELINUX is not configured.
	return mode, nil
}
