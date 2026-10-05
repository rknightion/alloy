package collectors

import (
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

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

type filesystemCollector struct {
	mountExclude, typeExclude *regexp.Regexp
	descs                     map[string]*prometheus.Desc
}

func newFilesystemCollector(cfg Configs, _ *slog.Logger) (agentless.Collector, error) {
	mount, err := regexp.Compile(cfg.Filesystem.MountPointsExclude)
	if err != nil {
		return nil, fmt.Errorf("mount points exclude: %w", err)
	}
	fs, err := regexp.Compile(cfg.Filesystem.FSTypesExclude)
	if err != nil {
		return nil, fmt.Errorf("filesystem types exclude: %w", err)
	}
	c := &filesystemCollector{descs: map[string]*prometheus.Desc{}}
	if cfg.Filesystem.MountPointsExclude != "" {
		c.mountExclude = mount
	}
	if cfg.Filesystem.FSTypesExclude != "" {
		c.typeExclude = fs
	}
	for suffix, help := range map[string]string{
		"size_bytes":   "Filesystem size in bytes.",
		"avail_bytes":  "Filesystem space available to non-root users in bytes.",
		"free_bytes":   "Filesystem free space in bytes.",
		"files":        "Filesystem total file nodes.",
		"files_free":   "Filesystem total free file nodes.",
		"readonly":     "Filesystem read-only status.",
		"device_error": "Whether an error occurred while getting statistics for the given device.",
	} {
		c.descs[suffix] = prometheus.NewDesc(agentless.Namespace+"_filesystem_"+suffix, help, []string{"device", "fstype", "mountpoint"}, nil)
	}
	return c, nil
}

// Name implements agentless.Collector.
func (c *filesystemCollector) Name() string { return "filesystem" }

// Reads implements agentless.Collector.
func (c *filesystemCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.CommandRead("df", "-kPT"), agentless.CommandRead("df", "-iPT"), agentless.FileRead("/proc/self/mounts")}
}

// Update implements agentless.Collector.
func (c *filesystemCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	reads := c.Reads()
	blocks, err := filesystemDF(in, reads[0])
	if err != nil {
		return err
	}
	inodes, err := filesystemDF(in, reads[1])
	if err != nil {
		return err
	}
	mountResult, ok := in[reads[2].ID]
	if !ok || mountResult.NotExist {
		return fmt.Errorf("filesystem mounts missing")
	}
	mounts, err := in.Output(reads[2])
	if err != nil {
		return err
	}
	seen := map[filesystemKey]bool{}
	for _, line := range strings.Split(string(mounts), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 6 {
			return fmt.Errorf("malformed filesystem mount row %q", line)
		}
		key := filesystemKey{filesystemUnescape(fields[0]), fields[2], filesystemUnescape(fields[1])}
		if seen[key] {
			continue
		}
		seen[key] = true
		if c.mountExclude != nil && c.mountExclude.MatchString(key.mount) || c.typeExclude != nil && c.typeExclude.MatchString(key.fstype) {
			continue
		}
		emit := func(suffix string, value float64) {
			ch <- prometheus.MustNewConstMetric(c.descs[suffix], prometheus.GaugeValue, value, key.device, key.fstype, key.mount)
		}
		b, bok := blocks[key]
		i, iok := inodes[key]
		if !bok || !iok {
			emit("device_error", 1)
			continue
		}
		emit("device_error", 0)
		emit("size_bytes", b.total*1024)
		emit("free_bytes", (b.total-b.used)*1024)
		emit("avail_bytes", b.available*1024)
		emit("files", i.total)
		emit("files_free", i.available)
		readonly := float64(0)
		for _, option := range strings.Split(fields[3], ",") {
			if option == "ro" {
				readonly = 1
			}
		}
		emit("readonly", readonly)
	}
	return nil
}

type filesystemKey struct{ device, fstype, mount string }
type filesystemUsage struct{ total, used, available float64 }

// df -P keeps each record on one line, including long device names. The mount
// point occupies the remainder of the row and may contain literal spaces.
// Exit 1 is useful GNU output when another mount failed; missing rows are
// reported as device_error using the mount table, not silently dropped.
func filesystemDF(in agentless.Input, read agentless.Read) (map[filesystemKey]filesystemUsage, error) {
	result, ok := in[read.ID]
	if !ok || result.NotExist || result.Truncated || result.TimedOut || result.ExitStatus < 0 || result.ExitStatus > 1 {
		return nil, fmt.Errorf("filesystem read %q unavailable", read.ID)
	}
	lines := strings.Split(strings.TrimSpace(string(result.Output)), "\n")
	if len(lines) == 0 || !strings.HasPrefix(strings.TrimSpace(lines[0]), "Filesystem") {
		return nil, fmt.Errorf("filesystem read %q has no df header", read.ID)
	}
	out := map[filesystemKey]filesystemUsage{}
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 7 {
			return nil, fmt.Errorf("malformed df row %q", line)
		}
		var values [3]float64
		for j := range values {
			// Some filesystems do not expose inode counts; GNU prints '-' for them.
			if f[j+2] == "-" && len(read.Argv) > 1 && read.Argv[1] == "-iPT" {
				continue
			}
			n, err := strconv.ParseUint(f[j+2], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid df count %q: %w", f[j+2], err)
			}
			values[j] = float64(n)
		}
		if values[1] > values[0] {
			return nil, fmt.Errorf("df used exceeds total in %q", line)
		}
		key := filesystemKey{filesystemUnescape(f[0]), f[1], filesystemUnescape(strings.Join(f[6:], " "))}
		out[key] = filesystemUsage{values[0], values[1], values[2]}
	}
	return out, nil
}

// Linux proc mounts escapes spaces, tabs, newlines and backslashes as octal.
// Decode once so an escaped backslash followed by digits stays literal.
func filesystemUnescape(s string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
}
