package collectors

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
)

func init() {
	Register(Registration{Name: "vmstat", OS: "linux", DefaultEnabled: true, Factory: newVmstatCollector})
}

// Match node_exporter's default collector.vmstat.fields flag. No target field
// names are retained until they pass this filter and the frozen family cap.
var vmstatFields = regexp.MustCompile(`^(oom_kill|pgpg|pswp|pg.*fault).*`)

const maxVmstatFields = 500

type vmstatCollector struct{}

func newVmstatCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &vmstatCollector{}, nil
}

// Name implements agentless.Collector.
func (c *vmstatCollector) Name() string { return "vmstat" }

// Reads implements agentless.Collector.
func (c *vmstatCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/vmstat")}
}

// Update implements agentless.Collector.
func (c *vmstatCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	read := c.Reads()[0]
	result := in[read.ID]
	if result.NotExist && !result.TimedOut && !result.Truncated {
		return nil
	}
	output, err := in.Output(read)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	var metrics []prometheus.Metric
	seen := make(map[string]bool)
	rows := 0
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		// Split without a per-line fields slice or copying the target's key.
		i := bytes.IndexAny(line, " \t")
		if i < 1 {
			return fmt.Errorf("vmstat: malformed line")
		}
		key, raw := line[:i], bytes.TrimSpace(line[i:])
		if len(raw) == 0 || bytes.ContainsAny(raw, " \t\r\n") {
			return fmt.Errorf("vmstat: malformed value")
		}
		value, err := strconv.ParseFloat(string(raw), 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return fmt.Errorf("vmstat: invalid value")
		}
		rows++
		if !vmstatFields.Match(key) {
			continue
		}
		if len(seen) == maxVmstatFields {
			return fmt.Errorf("vmstat: field limit exceeded (%d)", maxVmstatFields)
		}
		name := string(key)
		if !validMeminfoKey(name) || seen[name] {
			return fmt.Errorf("vmstat: invalid or duplicate field %q", name)
		}
		seen[name] = true
		desc := prometheus.NewDesc(agentless.Namespace+"_vmstat_"+name, "/proc/vmstat information field "+name+".", nil, nil)
		metric, err := prometheus.NewConstMetric(desc, prometheus.UntypedValue, value)
		if err != nil {
			return fmt.Errorf("vmstat: metric: %w", err)
		}
		metrics = append(metrics, metric)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("vmstat: scan: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("vmstat: no fields")
	}
	// Validate the full bounded snapshot before emitting any series.
	for _, metric := range metrics {
		ch <- metric
	}
	return nil
}
