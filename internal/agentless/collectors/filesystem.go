package collectors

import (
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

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

const (
	filesystemMaxMounts = 10000
	filesystemMaxDFRows = 10000
)

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
	mountRows := 0
	for _, line := range strings.Split(string(mounts), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		mountRows++
		if mountRows > filesystemMaxMounts {
			return fmt.Errorf("filesystem mount row limit exceeded")
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

// Both endpoint tries are global: each row traverses its source prefix and
// reversed mount suffix only once, including when sources or mounts overlap.
type filesystemEndpointIndex struct {
	label     string
	children  map[byte]*filesystemEndpointIndex
	sourceIDs map[int]uint16
	terminal  bool
	keys      map[uint16]map[int]filesystemKey
	sources   *filesystemSourceIndex
}

// A persistent direct-address radix table of source IDs. Four nibble lookups
// cover every ID under the 10000-mount cap. Each mount terminal inherits its
// ancestors' table and prepends its own matches; no source-specific suffix
// traversal is needed. Copying a path takes five bounded-size allocations.
type filesystemSourceIndex struct {
	children [16]*filesystemSourceIndex
	matches  *filesystemMountMatches
}

type filesystemMountMatches struct {
	depth int
	keys  map[int]filesystemKey
	next  *filesystemMountMatches
}

func (n *filesystemSourceIndex) get(id uint16) *filesystemMountMatches {
	for shift := 12; shift >= 0 && n != nil; shift -= 4 {
		n = n.children[(id>>shift)&15]
	}
	if n == nil {
		return nil
	}
	return n.matches
}

func (n *filesystemSourceIndex) with(id uint16, shift int, matches *filesystemMountMatches) *filesystemSourceIndex {
	out := &filesystemSourceIndex{}
	if n != nil {
		*out = *n
	}
	if shift < 0 {
		out.matches = matches
	} else {
		j := (id >> shift) & 15
		out.children[j] = out.children[j].with(id, shift-4, matches)
	}
	return out
}

type filesystemDFIndex struct {
	sources, mounts *filesystemEndpointIndex
	fstypes         map[string]int
}

type filesystemDFMatch struct {
	key    filesystemKey
	column int
}

type filesystemDFColumn struct {
	fields [5]string
	fstype int
}

func (n *filesystemEndpointIndex) insert(value string, reverse bool) *filesystemEndpointIndex {
	if reverse {
		b := []byte(value)
		slices.Reverse(b)
		value = string(b)
	}
	// Radix edges retain entire common substrings. Node count is bounded by
	// endpoint count rather than bytes, even for very long hostile names.
	for len(value) > 0 {
		if n.children == nil {
			n.children = map[byte]*filesystemEndpointIndex{}
		}
		child := n.children[value[0]]
		if child == nil {
			child = &filesystemEndpointIndex{label: value}
			n.children[value[0]] = child
			return child
		}
		common := 0
		for common < len(value) && common < len(child.label) && value[common] == child.label[common] {
			common++
		}
		if common < len(child.label) {
			branch := &filesystemEndpointIndex{label: child.label[:common], children: map[byte]*filesystemEndpointIndex{child.label[common]: child}}
			n.children[value[0]] = branch
			child.label = child.label[common:]
			child = branch
		}
		n = child
		value = value[common:]
	}
	return n
}

func filesystemIndex(mounts map[filesystemKey]string) *filesystemDFIndex {
	index := &filesystemDFIndex{sources: &filesystemEndpointIndex{}, mounts: &filesystemEndpointIndex{}, fstypes: map[string]int{}}
	var sourceCount uint16
	for key := range mounts {
		source := index.sources.insert(key.device, false)
		if !source.terminal {
			source.terminal = true
			source.sourceIDs = map[int]uint16{}
		}
		fstype, ok := index.fstypes[key.fstype]
		if !ok {
			fstype = len(index.fstypes)
			index.fstypes[key.fstype] = fstype
		}
		id, ok := source.sourceIDs[fstype]
		if !ok {
			id = sourceCount
			source.sourceIDs[fstype] = id
			sourceCount++
		}
		mount := index.mounts.insert(key.mount, true)
		if mount.keys == nil {
			mount.keys = map[uint16]map[int]filesystemKey{}
		}
		if mount.keys[id] == nil {
			mount.keys[id] = map[int]filesystemKey{}
		}
		mount.keys[id][fstype] = key
	}
	// Iterative construction also bounds stack use for nested mount names.
	type pending struct {
		n     *filesystemEndpointIndex
		depth int
	}
	stack := []pending{{index.mounts, 0}}
	for len(stack) > 0 {
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		n := item.n
		for id, keys := range n.keys {
			matches := &filesystemMountMatches{depth: item.depth, keys: keys, next: n.sources.get(id)}
			n.sources = n.sources.with(id, 12, matches)
		}
		for _, child := range n.children {
			child.sources = n.sources
			stack = append(stack, pending{child, item.depth + len(child.label)})
		}
	}
	return index
}

func (index *filesystemDFIndex) matches(line string) ([]filesystemDFMatch, map[int]filesystemDFColumn) {
	// Token byte spans retain strings.Fields' Unicode whitespace semantics.
	// nextField makes the five columns after any literal source an O(1) query,
	// even when many source endpoints lie in the same long whitespace run.
	type span struct{ start, end int }
	var fields []span
	start := -1
	for pos, r := range line {
		if unicode.IsSpace(r) {
			if start >= 0 {
				fields = append(fields, span{start, pos})
				start = -1
			}
		} else if start < 0 {
			start = pos
		}
	}
	if start >= 0 {
		fields = append(fields, span{start, len(line)})
	}
	nextField := make([]int, len(line)+1)
	field := len(fields)
	for pos := len(line); pos >= 0; pos-- {
		if field > 0 && pos == fields[field-1].start {
			field--
		}
		nextField[pos] = field
	}

	// For every possible suffix length, remember the last fully matched
	// mount-trie node's table. A source can then select the table immediately
	// before its fifth column, without rescanning any shared suffix bytes.
	suffix := make([]*filesystemSourceIndex, len(line)+1)
	n, depth := index.mounts, 0
	table := n.sources
	suffix[0] = table
	for depth < len(line) {
		child := n.children[line[len(line)-depth-1]]
		if child == nil || len(child.label) > len(line)-depth {
			break
		}
		matched := true
		for j := 0; j < len(child.label); j++ {
			if child.label[j] != line[len(line)-depth-j-1] {
				matched = false
				break
			}
		}
		if !matched {
			break
		}
		end := depth + len(child.label)
		for depth < end {
			depth++
			suffix[depth] = table
		}
		n, table = child, child.sources
		suffix[depth] = table
	}
	for depth < len(line) {
		depth++
		suffix[depth] = table
	}

	var matches []filesystemDFMatch
	columns := map[int]filesystemDFColumn{}
	for n, start := index.sources, 0; n != nil; {
		if !strings.HasPrefix(line[start:], n.label) {
			break
		}
		start += len(n.label)
		if n.terminal && start < len(line) && (line[start] == ' ' || line[start] == '\t') {
			first := nextField[start]
			if first+4 < len(fields) && fields[first+4].end < len(line) {
				end, paddingEnd := fields[first+4].end, len(line)
				if first+5 < len(fields) {
					paddingEnd = fields[first+5].start
				}
				column, ok := columns[first]
				if !ok {
					for j := range column.fields {
						f := fields[first+j]
						column.fields[j] = line[f.start:f.end]
					}
					column.fstype = -1
					if id, found := index.fstypes[column.fields[0]]; found {
						column.fstype = id
					}
					columns[first] = column
				}
				id, found := n.sourceIDs[column.fstype]
				var m *filesystemMountMatches
				if found {
					m = suffix[len(line)-end-1].get(id)
				}
				for ; m != nil && m.depth >= len(line)-paddingEnd; m = m.next {
					pos := len(line) - m.depth
					if line[pos-1] != ' ' && line[pos-1] != '\t' {
						continue
					}
					if key, ok := m.keys[column.fstype]; ok {
						matches = append(matches, filesystemDFMatch{key, first})
					}
				}
			}
		}
		if start == len(line) {
			break
		}
		n = n.children[line[start]]
	}
	return matches, columns
}

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
	if len(mounts) > filesystemMaxMounts {
		return nil, fmt.Errorf("filesystem mount limit exceeded")
	}
	index := filesystemIndex(mounts)
	out := map[filesystemKey]filesystemUsage{}
	rows := 0
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		rows++
		if rows > filesystemMaxDFRows {
			return nil, fmt.Errorf("filesystem df row limit exceeded")
		}
		matches, columns := index.matches(line)
		// Literal endpoint matching is already complete. Cache numeric parsing
		// by column span, not source, so whitespace variants cannot repeatedly
		// parse shared long fields.
		usageByColumn := map[int]filesystemUsage{}
		for _, match := range matches {
			if usage, ok := usageByColumn[match.column]; ok {
				out[match.key] = usage
				continue
			}
			f := columns[match.column].fields
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
			usage := filesystemUsage{values[0], values[1], values[2]}
			usageByColumn[match.column] = usage
			out[match.key] = usage
		}
	}
	return out, nil
}

// Linux proc mounts escapes spaces, tabs, newlines and backslashes as octal.
// Decode once so an escaped backslash followed by digits stays literal.
func filesystemUnescape(s string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
}
