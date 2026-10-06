package collectors

import (
	"fmt"
	"log/slog"
	"regexp"
	"slices"
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
	// Normalize df's localized header; -a includes duplicate/bind mounts.
	// Every argument is compiled in, including the environment assignment.
	return []agentless.Read{agentless.CommandRead("env", "LC_ALL=C", "df", "-akPT"), agentless.CommandRead("env", "LC_ALL=C", "df", "-aiPT"), agentless.FileRead("/proc/self/mounts")}
}

// Update implements agentless.Collector.
func (c *filesystemCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	reads := c.Reads()
	mountResult, ok := in[reads[2].ID]
	if !ok || mountResult.NotExist {
		return fmt.Errorf("filesystem mounts missing")
	}
	mounts, err := in.Output(reads[2])
	if err != nil {
		return err
	}
	keys := map[filesystemKey]string{}
	for _, line := range strings.Split(string(mounts), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 6 {
			return fmt.Errorf("malformed filesystem mount row %q", line)
		}
		key := filesystemKey{filesystemUnescape(fields[0]), fields[2], filesystemUnescape(fields[1])}
		keys[key] = fields[3]
	}
	blocks, err := filesystemDF(in, reads[0], keys)
	if err != nil {
		return err
	}
	inodes, err := filesystemDF(in, reads[1], keys)
	if err != nil {
		return err
	}
	for key, options := range keys {
		if c.mountExclude != nil && c.mountExclude.MatchString(key.mount) || c.typeExclude != nil && c.typeExclude.MatchString(key.fstype) {
			continue
		}
		emit := func(suffix string, value float64) {
			ch <- targetMetric(c.descs[suffix], prometheus.GaugeValue, value, key.device, key.fstype, key.mount)
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
		for _, option := range strings.Split(options, ",") {
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

// df -P keeps each record on one line, including long device names. Both the
// source and mount point may contain literal whitespace: match them against
// decoded mount metadata before splitting the five intervening columns.
// Exit 1 is useful GNU output when another mount failed; missing rows are
// reported as device_error using the mount table, not silently dropped.
func filesystemDF(in agentless.Input, read agentless.Read, mounts map[filesystemKey]string) (map[filesystemKey]filesystemUsage, error) {
	result, ok := in[read.ID]
	if !ok || result.NotExist || result.Truncated || result.TimedOut || result.ExitStatus < 0 || result.ExitStatus > 1 {
		return nil, fmt.Errorf("filesystem read %q unavailable", read.ID)
	}
	inodeRead := slices.Contains(read.Argv, "-aiPT")
	// Preserve endpoint whitespace, including the final mount's trailing space.
	lines := strings.Split(string(result.Output), "\n")
	if len(lines) == 0 || !strings.HasPrefix(strings.TrimSpace(lines[0]), "Filesystem") {
		return nil, fmt.Errorf("filesystem read %q has no df header", read.ID)
	}
	out := map[filesystemKey]filesystemUsage{}
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		for key := range mounts {
			// Match exact endpoints, leaving padding for Fields to remove. Do
			// not decode df text: unlike proc mounts it contains literal names.
			row := line
			if !strings.HasPrefix(row, key.device) || !strings.HasSuffix(row, key.mount) {
				continue
			}
			end := len(row) - len(key.mount)
			if end <= len(key.device) {
				continue
			}
			middle := row[len(key.device):end]
			if !strings.HasPrefix(middle, " ") && !strings.HasPrefix(middle, "\t") {
				continue
			}
			if !strings.HasSuffix(middle, " ") && !strings.HasSuffix(middle, "\t") {
				continue
			}
			f := strings.Fields(middle)
			if len(f) != 5 || f[0] != key.fstype && f[0] != "-" {
				continue
			}
			// GNU -a prints '-' for inaccessible/shadowed mounts. Leaving
			// the row absent reports device_error, not fictitious zero space.
			if f[0] == "-" || f[1] == "-" && !inodeRead {
				continue
			}
			var values [3]float64
			for j := range values {
				if f[j+1] == "-" && inodeRead {
					continue
				}
				if j == 2 {
					// f_bavail can be negative when reserved space is exhausted.
					n, err := strconv.ParseInt(f[j+1], 10, 64)
					if err != nil {
						return nil, fmt.Errorf("invalid df count %q: %w", f[j+1], err)
					}
					values[j] = float64(n)
				} else {
					n, err := strconv.ParseUint(f[j+1], 10, 64)
					if err != nil {
						return nil, fmt.Errorf("invalid df count %q: %w", f[j+1], err)
					}
					values[j] = float64(n)
				}
			}
			if values[1] > values[0] {
				return nil, fmt.Errorf("df used exceeds total in %q", line)
			}
			out[key] = filesystemUsage{values[0], values[1], values[2]}
		}
	}
	return out, nil
}

// Linux proc mounts escapes spaces, tabs, newlines and backslashes as octal.
// Decode once so an escaped backslash followed by digits stays literal.
func filesystemUnescape(s string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
}
