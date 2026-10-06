package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

var filesystemFamilies = []string{"node_filesystem_size_bytes", "node_filesystem_avail_bytes", "node_filesystem_free_bytes", "node_filesystem_files", "node_filesystem_files_free", "node_filesystem_readonly", "node_filesystem_device_error"}

func filesystemInput(t *testing.T, c agentless.Collector, flavor string) agentless.Input {
	t.Helper()
	root := filepath.Join("testdata", "filesystem", flavor)
	runner, err := agentlesstest.FromFS(root, map[string]string{agentless.CommandRead("env", "LC_ALL=C", "df", "-akPT").ID: filepath.Join(root, "blocks"), agentless.CommandRead("env", "LC_ALL=C", "df", "-aiPT").ID: filepath.Join(root, "inodes")}, c.Reads())
	require.NoError(t, err)
	results, err := runner.Run(context.Background(), agentless.Target{}, c.Reads())
	require.NoError(t, err)
	in := agentless.Input{}
	for _, r := range results {
		in[r.Read.ID] = r
	}
	return in
}

func filesystemMetrics(t *testing.T, c agentless.Collector, in agentless.Input) map[string][]*dto.Metric {
	t.Helper()
	ch := make(chan prometheus.Metric, 4096)
	require.NoError(t, c.Update(agentless.Target{}, in, ch))
	close(ch)
	out := map[string][]*dto.Metric{}
	for m := range ch {
		d := &dto.Metric{}
		require.NoError(t, m.Write(d))
		for _, name := range filesystemFamilies {
			if strings.Contains(m.Desc().String(), `fqName: "`+name+`"`) {
				out[name] = append(out[name], d)
			}
		}
	}
	return out
}

func TestFilesystemRealOutput(t *testing.T) {
	for _, flavor := range []string{"gnu", "busybox", "gnu-local"} {
		t.Run(flavor, func(t *testing.T) {
			c, err := newFilesystemCollector(DefaultConfigs(), nil)
			require.NoError(t, err)
			root := filepath.Join("testdata", "filesystem", flavor)
			conformance.Check(t, conformance.Case{Collector: c, Families: filesystemFamilies, Root: root, Commands: map[string]string{agentless.CommandRead("env", "LC_ALL=C", "df", "-akPT").ID: filepath.Join(root, "blocks"), agentless.CommandRead("env", "LC_ALL=C", "df", "-aiPT").ID: filepath.Join(root, "inodes")}, Expected: filepath.Join(root, "expected.prom")})
			in := filesystemInput(t, c, flavor)
			for _, read := range c.Reads()[:2] {
				r := in[read.ID]
				r.ExitStatus = 1
				in[read.ID] = r
			}
			metrics := filesystemMetrics(t, c, in)
			require.NotEmpty(t, metrics["node_filesystem_size_bytes"])
			for _, m := range metrics["node_filesystem_device_error"] {
				require.Zero(t, m.GetGauge().GetValue())
			}
		})
	}
}

// These outputs and statuses were observed from GNU df with one readable and
// one missing operand, rather than assigning exit 1 to a successful recording.
func TestFilesystemRecordedGNUExitOne(t *testing.T) {
	c, err := newFilesystemCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	in := filesystemInput(t, c, "gnu-exit1")
	data, err := os.ReadFile(filepath.Join("testdata", "filesystem", "gnu-exit1", "exits.json"))
	require.NoError(t, err)
	var exits map[string]int
	require.NoError(t, json.Unmarshal(data, &exits))
	for j, name := range []string{"blocks", "inodes"} {
		require.Equal(t, 1, exits[name])
		read := c.Reads()[j]
		result := in[read.ID]
		result.ExitStatus = exits[name]
		in[read.ID] = result
	}
	metrics := filesystemMetrics(t, c, in)
	require.Len(t, metrics["node_filesystem_size_bytes"], 1)
	require.Positive(t, metrics["node_filesystem_size_bytes"][0].GetGauge().GetValue())
	for _, metric := range metrics["node_filesystem_device_error"] {
		for _, label := range metric.Label {
			if label.GetName() == "mountpoint" && label.GetValue() == "/" {
				require.Zero(t, metric.GetGauge().GetValue())
			}
		}
	}
}

func TestFilesystemConfigAndErrors(t *testing.T) {
	for _, cfg := range []FilesystemConfig{{MountPointsExclude: "["}, {FSTypesExclude: "["}} {
		_, err := newFilesystemCollector(Configs{Filesystem: cfg}, nil)
		require.Error(t, err)
	}
	c, err := newFilesystemCollector(Configs{}, nil)
	require.NoError(t, err)
	in := filesystemInput(t, c, "gnu")
	for _, flag := range []string{"missing", "truncated", "timeout", "notexist", "exit"} {
		t.Run(flag, func(t *testing.T) {
			copyIn := agentless.Input{}
			for k, v := range in {
				copyIn[k] = v
			}
			id := c.Reads()[0].ID
			r := copyIn[id]
			switch flag {
			case "missing":
				delete(copyIn, id)
			case "truncated":
				r.Truncated = true
			case "timeout":
				r.TimedOut = true
			case "notexist":
				r.NotExist = true
			case "exit":
				r.ExitStatus = 2
			}
			if flag != "missing" {
				copyIn[id] = r
			}
			require.Error(t, c.Update(agentless.Target{}, copyIn, make(chan prometheus.Metric, 4096)))
		})
	}
	mounts := agentless.FileRead("/proc/self/mounts")
	in[mounts.ID] = agentless.Result{Read: mounts, Output: []byte("/dev/a /space\\040here ext4 ro,nosuid 0 0\n/dev/b /missing ext4 rw 0 0\n/dev/a /space\\040here ext4 ro 0 0\n")}
	for _, read := range c.Reads()[:2] {
		in[read.ID] = agentless.Result{Read: read, Output: []byte("Filesystem Type Blocks Used Available Capacity Mounted on\n/dev/a ext4 10 3 5 50% /space here\n")}
	}
	m := filesystemMetrics(t, c, in)
	require.Len(t, m["node_filesystem_size_bytes"], 1)
	require.Equal(t, float64(10240), m["node_filesystem_size_bytes"][0].GetGauge().GetValue())
	require.Equal(t, float64(7168), m["node_filesystem_free_bytes"][0].GetGauge().GetValue())
	require.Equal(t, float64(1), m["node_filesystem_readonly"][0].GetGauge().GetValue())
	require.Len(t, m["node_filesystem_device_error"], 2)
	in[c.Reads()[0].ID] = agentless.Result{Output: []byte("garbage")}
	require.Error(t, c.Update(agentless.Target{}, in, make(chan prometheus.Metric, 4096)))
}

// These regressions use real GNU/BusyBox output from local, invocation-owned
// tmpfs and bind mounts, not a node_exporter oracle. Legacy GNU df omits the
// duplicate mount; -a must restore its own row rather than infer its statistics.
func TestFilesystemDuplicateMounts(t *testing.T) {
	for _, flavor := range []string{"gnu-local", "busybox"} {
		t.Run(flavor, func(t *testing.T) {
			c, err := newFilesystemCollector(DefaultConfigs(), nil)
			require.NoError(t, err)
			in := filesystemProofInput(t, c, flavor, false)
			metrics := filesystemMetrics(t, c, in)
			for _, mount := range []string{"/proof/original", "/proof/duplicate"} {
				found := false
				for _, m := range metrics["node_filesystem_device_error"] {
					for _, label := range m.Label {
						if label.GetName() == "mountpoint" && label.GetValue() == mount {
							found = true
							require.Zero(t, m.GetGauge().GetValue(), mount)
						}
					}
				}
				require.True(t, found, mount)
			}
			require.Len(t, metrics["node_filesystem_size_bytes"], 2)
		})
	}
}

func TestFilesystemSourceSpaces(t *testing.T) {
	for _, flavor := range []string{"gnu-local", "busybox"} {
		t.Run(flavor, func(t *testing.T) {
			c, err := newFilesystemCollector(DefaultConfigs(), nil)
			require.NoError(t, err)
			m := filesystemMetrics(t, c, filesystemProofInput(t, c, flavor, true))
			require.Len(t, m["node_filesystem_size_bytes"], 1)
			require.Equal(t, float64(2048*1024), m["node_filesystem_size_bytes"][0].GetGauge().GetValue())
			labels := map[string]string{}
			for _, label := range m["node_filesystem_size_bytes"][0].Label {
				labels[label.GetName()] = label.GetValue()
			}
			require.Equal(t, map[string]string{"device": "source with spaces", "fstype": "tmpfs", "mountpoint": "/proof/space mount"}, labels)
			require.Zero(t, m["node_filesystem_device_error"][0].GetGauge().GetValue())
		})
	}
}

func filesystemProofInput(t *testing.T, c agentless.Collector, flavor string, spaces bool) agentless.Input {
	t.Helper()
	in := agentless.Input{}
	root := filepath.Join("testdata", "filesystem", flavor)
	for j, read := range c.Reads()[:2] {
		file := []string{"blocks", "inodes"}[j]
		if !strings.Contains(read.Argv[len(read.Argv)-1], "a") {
			file = "legacy-" + file
		}
		data, err := os.ReadFile(filepath.Join(root, file))
		require.NoError(t, err)
		lines := strings.Split(string(data), "\n")
		output := lines[0] + "\n"
		for _, line := range lines[1:] {
			if strings.Contains(line, "/proof/") && strings.Contains(line, "source with spaces") == spaces {
				output += line + "\n"
			}
		}
		in[read.ID] = agentless.Result{Read: read, Output: []byte(output)}
	}
	read := c.Reads()[2]
	data, err := os.ReadFile(filepath.Join(root, "proc/self/mounts"))
	require.NoError(t, err)
	var mounts string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "/proof/") && strings.Contains(line, `source\040with\040spaces`) == spaces {
			mounts += line + "\n"
		}
	}
	in[read.ID] = agentless.Result{Read: read, Output: []byte(mounts)}
	return in
}

// The fake df is the subprocess edge: it localizes its header unless the
// actual compiled read normalizes the inherited remote environment.
func TestFilesystemInheritedLocale(t *testing.T) {
	c, err := newFilesystemCollector(Configs{}, nil)
	require.NoError(t, err)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "df"), []byte(`#!/bin/sh
if [ "$LC_ALL" = C ]; then
  printf 'Filesystem Type Blocks Used Available Capacity Mounted on\n'
else
  printf 'Système de fichiers Type Blocs Utilisé Disponible Uti%% Monté sur\n'
fi
printf '/dev/a ext4 10 3 5 50%% /proof\n'
`), 0o700))
	in := agentless.Input{}
	for _, read := range c.Reads()[:2] {
		cmd := exec.Command("sh", "-c", strings.Join(read.Argv, " "))
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "LC_ALL=fr_FR.UTF-8")
		output, err := cmd.Output()
		require.NoError(t, err)
		in[read.ID] = agentless.Result{Read: read, Output: output}
	}
	read := c.Reads()[2]
	in[read.ID] = agentless.Result{Read: read, Output: []byte("/dev/a /proof ext4 rw 0 0\n")}
	metrics := filesystemMetrics(t, c, in)
	require.Equal(t, float64(10240), metrics["node_filesystem_size_bytes"][0].GetGauge().GetValue())
	require.Equal(t, float64(10), metrics["node_filesystem_files"][0].GetGauge().GetValue())
}

func TestFilesystemEndpointWhitespace(t *testing.T) {
	c, err := newFilesystemCollector(Configs{}, nil)
	require.NoError(t, err)
	for _, endpoints := range []struct{ device, mount string }{
		{" leading source", "/proof"},
		{"source", "/proof trailing "},
		{strings.Repeat("source", 16000), "/" + strings.Repeat("mount", 16000)},
		{"source", "/proof"},
		{"source extended", "/proof extended"},
	} {
		in := agentless.Input{}
		for _, read := range c.Reads()[:2] {
			in[read.ID] = agentless.Result{Read: read, Output: []byte("Filesystem Type Blocks Used Available Capacity Mounted on\n" + endpoints.device + " ext4 10 3 5 50% " + endpoints.mount + "\n")}
		}
		read := c.Reads()[2]
		in[read.ID] = agentless.Result{Read: read, Output: []byte(strings.ReplaceAll(endpoints.device, " ", `\040`) + " " + strings.ReplaceAll(endpoints.mount, " ", `\040`) + " ext4 rw 0 0\n")}
		metrics := filesystemMetrics(t, c, in)
		require.Len(t, metrics["node_filesystem_size_bytes"], 1)
		require.Equal(t, float64(10240), metrics["node_filesystem_size_bytes"][0].GetGauge().GetValue())
		labels := map[string]string{}
		for _, label := range metrics["node_filesystem_size_bytes"][0].Label {
			labels[label.GetName()] = label.GetValue()
		}
		require.Equal(t, endpoints.device, labels["device"])
		require.Equal(t, endpoints.mount, labels["mountpoint"])
	}
}

// Exercise the collector seam, including duplicate rows (not just map size).
func TestFilesystemInputBounds(t *testing.T) {
	c, err := newFilesystemCollector(Configs{}, nil)
	require.NoError(t, err)
	for _, count := range []int{10000, 10001, 55000} {
		for _, overflow := range []string{"mounts", "blocks", "inodes"} {
			t.Run(fmt.Sprintf("%s/%d", overflow, count), func(t *testing.T) {
				in := agentless.Input{}
				for j, read := range c.Reads() {
					rows := 1
					if []string{"blocks", "inodes", "mounts"}[j] == overflow {
						rows = count
					}
					output := strings.Repeat("/dev/a /proof ext4 rw 0 0\n", rows)
					if j < 2 {
						output = "Filesystem Type Blocks Used Available Capacity Mounted on\n" + strings.Repeat("/dev/a ext4 10 3 5 50% /proof\n", rows)
					}
					in[read.ID] = agentless.Result{Read: read, Output: []byte(output)}
				}
				start := time.Now()
				err := c.Update(agentless.Target{}, in, make(chan prometheus.Metric, 8))
				require.Less(t, time.Since(start), time.Second)
				if count > 10000 {
					require.ErrorContains(t, err, "limit")
				} else {
					require.NoError(t, err)
				}
			})
		}
	}
}

func TestFilesystemHostileCombined(t *testing.T) {
	c, err := newFilesystemCollector(Configs{}, nil)
	require.NoError(t, err)
	var mounts, df strings.Builder
	df.WriteString("Filesystem Type Blocks Used Available Capacity Mounted on\n")
	for j := range 55000 {
		fmt.Fprintf(&mounts, "d%d /m%d ext4 rw 0 0\n", j, j)
		fmt.Fprintf(&df, "d%d ext4 10 3 5 50%% /m%d\n", j, j)
	}
	in := agentless.Input{}
	for j, read := range c.Reads() {
		output := df.String()
		if j == 2 {
			output = mounts.String()
		}
		in[read.ID] = agentless.Result{Read: read, Output: []byte(output)}
	}
	start := time.Now()
	ch := make(chan prometheus.Metric, 1)
	require.ErrorContains(t, c.Update(agentless.Target{}, in, ch), "limit")
	require.Less(t, time.Since(start), time.Second)
	require.Empty(t, ch)
}

func TestFilesystemIndexedMatching(t *testing.T) {
	c, err := newFilesystemCollector(Configs{}, nil)
	require.NoError(t, err)
	var mounts, df strings.Builder
	df.WriteString("Filesystem Type Blocks Used Available Capacity Mounted on\n")
	for j := range 10000 {
		fmt.Fprintf(&mounts, "/dev/d%d /m%d ext4 rw 0 0\n", j, j)
		fmt.Fprintf(&df, "/dev/d%d ext4 10 3 5 50%% /m%d\n", j, j)
	}
	in := agentless.Input{}
	for j, read := range c.Reads() {
		output := df.String()
		if j == 2 {
			output = mounts.String()
		}
		in[read.ID] = agentless.Result{Read: read, Output: []byte(output)}
	}
	ch := make(chan prometheus.Metric, 70000)
	start := time.Now()
	require.NoError(t, c.Update(agentless.Target{}, in, ch))
	require.Less(t, time.Since(start), time.Second)
	require.Len(t, ch, 70000)
	for len(ch) > 0 {
		metric := <-ch
		if strings.Contains(metric.Desc().String(), "node_filesystem_device_error") {
			value := &dto.Metric{}
			require.NoError(t, metric.Write(value))
			require.Zero(t, value.GetGauge().GetValue())
		}
	}
}

func TestFilesystemOverlappingMounts(t *testing.T) {
	c, err := newFilesystemCollector(Configs{}, nil)
	require.NoError(t, err)
	var mounts, df strings.Builder
	df.WriteString("Filesystem Type Blocks Used Available Capacity Mounted on\n")
	for j := 1; j <= 580; j++ {
		mount := strings.TrimSpace(strings.Repeat("/m ", j))
		fmt.Fprintf(&mounts, "x %s ext4 rw 0 0\n", strings.ReplaceAll(mount, " ", `\040`))
		fmt.Fprintf(&df, "x ext4 10 3 5 50%% %s\n", mount)
	}
	in := agentless.Input{}
	for j, read := range c.Reads() {
		output := df.String()
		if j == 2 {
			output = mounts.String()
		}
		require.Less(t, len(output), 1<<20)
		in[read.ID] = agentless.Result{Read: read, Output: []byte(output)}
	}
	ch := make(chan prometheus.Metric, 580*7)
	start := time.Now()
	require.NoError(t, c.Update(agentless.Target{}, in, ch))
	require.Less(t, time.Since(start), time.Second)
	require.Len(t, ch, 580*7)
}

func TestFilesystemOverlappingSources(t *testing.T) {
	c, err := newFilesystemCollector(Configs{}, nil)
	require.NoError(t, err)
	var mounts, df strings.Builder
	df.WriteString("Filesystem Type Blocks Used Available Capacity Mounted on\n")
	mount := strings.Repeat("/a", 500)
	for j := 1; j <= 400; j++ {
		source := strings.TrimSpace(strings.Repeat("s ", j))
		fmt.Fprintf(&mounts, "%s %s ext4 rw 0 0\n", strings.ReplaceAll(source, " ", `\040`), mount)
		fmt.Fprintf(&df, "%s ext4 10 3 5 50%% %s\n", source, mount)
	}
	in := agentless.Input{}
	total := 0
	for j, read := range c.Reads() {
		output := df.String()
		if j == 2 {
			output = mounts.String()
		}
		require.Less(t, len(output), 1<<20)
		total += len(output)
		in[read.ID] = agentless.Result{Read: read, Output: []byte(output)}
	}
	require.Less(t, total, 8<<20)
	ch := make(chan prometheus.Metric, 400*7)
	start := time.Now()
	require.NoError(t, c.Update(agentless.Target{}, in, ch))
	elapsed := time.Since(start)
	t.Logf("Collector.Update: %s", elapsed)
	require.Less(t, elapsed, time.Second)
	require.Len(t, ch, 400*7)
}

// Compare the index with the original literal-endpoint/Fields contract,
// including endpoint whitespace that must not be normalized or decoded.
func TestFilesystemEndpointIndexConformance(t *testing.T) {
	mounts := map[filesystemKey]string{}
	for _, source := range []string{"s", "s s", " s", "s ", "s\t", "s \t", "s\u2003"} {
		for _, mount := range []string{"/m", "/m /m", " /m", "\t/m", " \t/m", "\u2003/m", "/m ", " "} {
			for _, fstype := range []string{"ext4", "tmpfs"} {
				mounts[filesystemKey{source, fstype, mount}] = "rw"
			}
		}
	}
	index := filesystemIndex(mounts)
	for key := range mounts {
		for _, padding := range []string{" ", "\t", " \u2003\t", "\u2003 "} {
			line := key.device + padding + key.fstype + " 10\u20033\t5 50%" + padding + key.mount
			want := map[filesystemKey]bool{}
			for candidate := range mounts {
				if !strings.HasPrefix(line, candidate.device) || !strings.HasSuffix(line, candidate.mount) {
					continue
				}
				start, end := len(candidate.device), len(line)-len(candidate.mount)
				if end <= start || line[start] != ' ' && line[start] != '\t' || line[end-1] != ' ' && line[end-1] != '\t' {
					continue
				}
				fields := strings.Fields(line[start:end])
				if len(fields) == 5 && fields[0] == candidate.fstype {
					want[candidate] = true
				}
			}
			matches, _ := index.matches(line)
			got := map[filesystemKey]bool{}
			for _, match := range matches {
				require.False(t, got[match.key], "duplicate match for %q", line)
				got[match.key] = true
			}
			require.Equal(t, want, got, "line %q", line)
		}
	}
}

func TestFilesystemDefaults(t *testing.T) {
	require.Equal(t, `^/(dev|proc|run/credentials/.+|sys|var/lib/docker/.+|var/lib/containers/storage/.+)($|/)`, DefaultFilesystemConfig.MountPointsExclude)
	require.Equal(t, `^(autofs|binfmt_misc|bpf|cgroup2?|configfs|debugfs|devpts|devtmpfs|fusectl|hugetlbfs|iso9660|mqueue|nsfs|overlay|proc|procfs|pstore|rpc_pipefs|securityfs|selinuxfs|squashfs|sysfs|tracefs)$`, DefaultFilesystemConfig.FSTypesExclude)
	c, err := newFilesystemCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	for _, r := range c.Reads() {
		require.NoError(t, r.Validate())
	}
	for _, flavor := range []string{"gnu", "busybox"} {
		_, err := os.Stat(filepath.Join("testdata", "filesystem", flavor, "expected.prom"))
		require.NoError(t, err)
	}
}
