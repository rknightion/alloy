package collectors

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
)

func init() {
	Register(Registration{Name: "netdev", OS: "linux", DefaultEnabled: true, Factory: newNetdevCollector})
}

// NetdevConfig holds the netdev collector options. Both fields are regular
// expressions. A non-empty DeviceInclude takes precedence and DeviceExclude is
// then ignored.
type NetdevConfig struct {
	DeviceExclude string
	DeviceInclude string
}

// DefaultNetdevConfig matches node_exporter's defaults.
var DefaultNetdevConfig = NetdevConfig{}

type netdevCollector struct{}

func newNetdevCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &netdevCollector{}, nil
}

// Name implements agentless.Collector.
func (c *netdevCollector) Name() string { return "netdev" }

// Reads implements agentless.Collector.
func (c *netdevCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/net/dev")}
}

// Update implements agentless.Collector.
func (c *netdevCollector) Update(_ agentless.Target, _ agentless.Input, _ chan<- prometheus.Metric) error {
	return agentless.ErrNotImplemented
}
