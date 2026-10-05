package collectors

import (
	"log/slog"

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
func (c *meminfoCollector) Update(_ agentless.Target, _ agentless.Input, _ chan<- prometheus.Metric) error {
	return agentless.ErrNotImplemented
}
