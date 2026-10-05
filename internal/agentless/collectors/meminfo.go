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
	Register(Registration{Name: "meminfo", OS: "linux", DefaultEnabled: true, Factory: newMeminfoCollector})
}

type meminfoCollector struct{}

func newMeminfoCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &meminfoCollector{}, nil
}

// Name implements agentless.Collector.
func (c *meminfoCollector) Name() string { return "meminfo" }

// Reads implements agentless.Collector.
func (c *meminfoCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/meminfo")}
}

// Update implements agentless.Collector.
func (c *meminfoCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	output, err := in.Output(c.Reads()[0])
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	metrics := make([]prometheus.Metric, 0)
	seen := make(map[string]bool)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if (len(fields) != 2 && len(fields) != 3) || !strings.HasSuffix(fields[0], ":") {
			return fmt.Errorf("meminfo: malformed line %q", scanner.Text())
		}
		key := strings.TrimSuffix(fields[0], ":")
		key = strings.NewReplacer("(", "_", ")", "").Replace(key)
		if key == "" || !validMeminfoKey(key) {
			return fmt.Errorf("meminfo: invalid field %q", fields[0])
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return fmt.Errorf("meminfo: invalid value for %s: %w", key, err)
		}
		v := float64(value)
		if len(fields) == 3 {
			if fields[2] != "kB" {
				return fmt.Errorf("meminfo: unsupported unit %q", fields[2])
			}
			key += "_bytes"
			v *= 1024
		}
		if seen[key] {
			return fmt.Errorf("meminfo: duplicate field %s", key)
		}
		seen[key] = true
		desc := prometheus.NewDesc(agentless.Namespace+"_memory_"+key, "Memory information field "+key+".", nil, nil)
		metric, err := prometheus.NewConstMetric(desc, prometheus.GaugeValue, v)
		if err != nil {
			return fmt.Errorf("meminfo: metric %s: %w", key, err)
		}
		metrics = append(metrics, metric)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("meminfo: read: %w", err)
	}
	if len(metrics) == 0 {
		return fmt.Errorf("meminfo: no fields")
	}
	for _, metric := range metrics {
		ch <- metric
	}
	return nil
}

func validMeminfoKey(key string) bool {
	for i, r := range key {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r == '_' || (i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}
