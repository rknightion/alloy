package collectors

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	runner, err := agentlesstest.FromFS(root, map[string]string{agentless.CommandRead("df", "-kPT").ID: filepath.Join(root, "blocks"), agentless.CommandRead("df", "-iPT").ID: filepath.Join(root, "inodes")}, c.Reads())
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
	for _, flavor := range []string{"gnu", "busybox"} {
		t.Run(flavor, func(t *testing.T) {
			c, err := newFilesystemCollector(DefaultConfigs(), nil)
			require.NoError(t, err)
			root := filepath.Join("testdata", "filesystem", flavor)
			conformance.Check(t, conformance.Case{Collector: c, Families: filesystemFamilies, Root: root, Commands: map[string]string{agentless.CommandRead("df", "-kPT").ID: filepath.Join(root, "blocks"), agentless.CommandRead("df", "-iPT").ID: filepath.Join(root, "inodes")}, Expected: filepath.Join(root, "expected.prom")})
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
