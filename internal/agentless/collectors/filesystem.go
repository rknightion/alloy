package collectors

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
)

func init() {
	Register(Registration{Name: "filesystem", OS: "linux", DefaultEnabled: true, Factory: newFilesystemCollector})
}

// FilesystemConfig holds the filesystem collector options. Both fields are
// regular expressions.
type FilesystemConfig struct {
	MountPointsExclude string
	FSTypesExclude     string
}

// DefaultFilesystemConfig matches node_exporter's defaults.
var DefaultFilesystemConfig = FilesystemConfig{
	MountPointsExclude: `^/(dev|proc|run/credentials/.+|sys|var/lib/docker/.+|var/lib/containers/storage/.+)($|/)`,
	FSTypesExclude:     `^(autofs|binfmt_misc|bpf|cgroup2?|configfs|debugfs|devpts|devtmpfs|fusectl|hugetlbfs|iso9660|mqueue|nsfs|overlay|proc|procfs|pstore|rpc_pipefs|securityfs|selinuxfs|squashfs|sysfs|tracefs)$`,
}

type filesystemCollector struct{}

func newFilesystemCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &filesystemCollector{}, nil
}

// Name implements agentless.Collector.
func (c *filesystemCollector) Name() string { return "filesystem" }

// Reads implements agentless.Collector.
func (c *filesystemCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.CommandRead("df", "-kPT"), agentless.CommandRead("df", "-iPT"), agentless.FileRead("/proc/self/mounts")}
}

// Update implements agentless.Collector.
func (c *filesystemCollector) Update(_ agentless.Target, _ agentless.Input, _ chan<- prometheus.Metric) error {
	return agentless.ErrNotImplemented
}
