package collectors

import (
	"log/slog"

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

// Update implements agentless.Collector.
func (c *statCollector) Update(_ agentless.Target, _ agentless.Input, _ chan<- prometheus.Metric) error {
	return agentless.ErrNotImplemented
}
