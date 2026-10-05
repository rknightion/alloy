package collectors

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
)

func init() {
	Register(Registration{Name: "loadavg", OS: "linux", DefaultEnabled: true, Factory: newLoadavgCollector})
}

type loadavgCollector struct{}

func newLoadavgCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &loadavgCollector{}, nil
}

// Name implements agentless.Collector.
func (c *loadavgCollector) Name() string { return "loadavg" }

// Reads implements agentless.Collector.
func (c *loadavgCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/loadavg")}
}

// Update implements agentless.Collector.
func (c *loadavgCollector) Update(_ agentless.Target, _ agentless.Input, _ chan<- prometheus.Metric) error {
	return agentless.ErrNotImplemented
}
