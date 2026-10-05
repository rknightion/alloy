package collectors

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
)

func init() {
	Register(Registration{Name: "uname", OS: "linux", DefaultEnabled: true, Factory: newUnameCollector})
}

type unameCollector struct{}

func newUnameCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &unameCollector{}, nil
}

// Name implements agentless.Collector.
func (c *unameCollector) Name() string { return "uname" }

// Reads implements agentless.Collector.
func (c *unameCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.CommandRead("uname", "-s"), agentless.CommandRead("uname", "-n"), agentless.CommandRead("uname", "-r"), agentless.CommandRead("uname", "-v"), agentless.CommandRead("uname", "-m")}
}

// Update implements agentless.Collector.
func (c *unameCollector) Update(_ agentless.Target, _ agentless.Input, _ chan<- prometheus.Metric) error {
	return agentless.ErrNotImplemented
}
