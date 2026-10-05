package collectors

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
)

func init() {
	Register(Registration{Name: "cpu", OS: "linux", DefaultEnabled: true, Factory: newCPUCollector})
}

type cpuCollector struct{}

func newCPUCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &cpuCollector{}, nil
}

// Name implements agentless.Collector.
func (c *cpuCollector) Name() string { return "cpu" }

// Reads implements agentless.Collector.
func (c *cpuCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/stat")}
}

// Update implements agentless.Collector.
func (c *cpuCollector) Update(_ agentless.Target, _ agentless.Input, _ chan<- prometheus.Metric) error {
	return agentless.ErrNotImplemented
}
