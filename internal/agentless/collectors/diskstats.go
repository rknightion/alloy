package collectors

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
)

func init() {
	Register(Registration{Name: "diskstats", OS: "linux", DefaultEnabled: true, Factory: newDiskstatsCollector})
}

// DiskstatsConfig holds the diskstats collector options. Both fields are
// regular expressions. A non-empty DeviceInclude takes precedence and
// DeviceExclude is then ignored, so setting only DeviceInclude over the
// defaults works.
type DiskstatsConfig struct {
	DeviceExclude string
	DeviceInclude string
}

// DefaultDiskstatsConfig matches node_exporter's defaults.
var DefaultDiskstatsConfig = DiskstatsConfig{
	DeviceExclude: `^(ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\d+n\d+p)\d+$`,
}

type diskstatsCollector struct{}

func newDiskstatsCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &diskstatsCollector{}, nil
}

// Name implements agentless.Collector.
func (c *diskstatsCollector) Name() string { return "diskstats" }

// Reads implements agentless.Collector.
func (c *diskstatsCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/diskstats")}
}

// Update implements agentless.Collector.
func (c *diskstatsCollector) Update(_ agentless.Target, _ agentless.Input, _ chan<- prometheus.Metric) error {
	return agentless.ErrNotImplemented
}
