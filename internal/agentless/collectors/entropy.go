package collectors

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	Register(Registration{Name: "entropy", OS: "linux", DefaultEnabled: true, Factory: newEntropyCollector})
}

type entropyCollector struct{}

func newEntropyCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &entropyCollector{}, nil
}

// Name implements agentless.Collector.
func (c *entropyCollector) Name() string { return "entropy" }

// Reads implements agentless.Collector.
func (c *entropyCollector) Reads() []agentless.Read {
	return []agentless.Read{
		agentless.FileRead("/proc/sys/kernel/random/entropy_avail"),
		agentless.FileRead("/proc/sys/kernel/random/poolsize"),
	}
}

// Update implements agentless.Collector.
func (c *entropyCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	names := []string{"entropy_available_bits", "entropy_pool_size_bits"}
	helps := []string{"Bits of available entropy.", "Bits of entropy pool."}
	metrics := make([]prometheus.Metric, 0, 2)
	for i, read := range c.Reads() {
		// Missing optional kernel files omit only their own family. All other
		// read failures must still fail this collector.
		if result, ok := in[read.ID]; ok && result.NotExist && !result.TimedOut && !result.Truncated {
			continue
		}
		output, err := in.Output(read)
		if err != nil {
			return err
		}
		value, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
		if err != nil {
			return fmt.Errorf("entropy: invalid %s: %w", read.Path, err)
		}
		metrics = append(metrics, prometheus.MustNewConstMetric(
			prometheus.NewDesc(agentless.Namespace+"_"+names[i], helps[i], nil, nil), prometheus.GaugeValue, float64(value)))
	}
	// Validate the whole snapshot before emitting any series.
	for _, metric := range metrics {
		ch <- metric
	}
	return nil
}
