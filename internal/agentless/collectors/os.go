package collectors

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
)

func init() {
	Register(Registration{Name: "os", OS: "linux", DefaultEnabled: true, Factory: newOSCollector})
}

type osCollector struct{}

func newOSCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &osCollector{}, nil
}

// Name implements agentless.Collector.
func (c *osCollector) Name() string { return "os" }

// Reads implements agentless.Collector.
func (c *osCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/etc/os-release"), agentless.FileRead("/usr/lib/os-release")}
}

// Update implements agentless.Collector.
func (c *osCollector) Update(_ agentless.Target, _ agentless.Input, _ chan<- prometheus.Metric) error {
	return agentless.ErrNotImplemented
}
