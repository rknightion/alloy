//go:build !race

package collectors

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

func TestFilesystemInputBoundsTiming(t *testing.T) {
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

func TestFilesystemHostileCombinedTiming(t *testing.T) {
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

func TestFilesystemIndexedMatchingTiming(t *testing.T) {
	c, err := newFilesystemCollector(Configs{}, nil)
	require.NoError(t, err)
	input := func(count int) agentless.Input {
		var mounts, df strings.Builder
		df.WriteString("Filesystem Type Blocks Used Available Capacity Mounted on\n")
		for j := range count {
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
		return in
	}
	// Keep 2n at the original 10000-row limit. Time the real Update path,
	// excluding fixture construction, channel allocation and metric inspection.
	inputs := []agentless.Input{input(5000), input(10000)}
	channels := []chan prometheus.Metric{make(chan prometheus.Metric, 35000), make(chan prometheus.Metric, 70000)}
	measure := func(size int) time.Duration {
		for len(channels[size]) > 0 {
			<-channels[size]
		}
		start := time.Now()
		err := c.Update(agentless.Target{}, inputs[size], channels[size])
		elapsed := time.Since(start)
		require.NoError(t, err)
		return elapsed
	}
	// Warm both sizes, then alternate their order to avoid a systematic bias.
	// Medians of five samples resist occasional scheduler/GC pauses under -race.
	measure(0)
	measure(1)
	var timings [2][]time.Duration
	for sample := range 5 {
		for offset := range 2 {
			size := (sample + offset) % 2
			timings[size] = append(timings[size], measure(size))
		}
	}
	for _, samples := range timings {
		slices.Sort(samples)
	}
	small, large := timings[0][2], timings[1][2]
	ratio := float64(large) / float64(small)
	t.Logf("Collector.Update median: n=5000 %s, 2n=10000 %s, ratio=%.3f", small, large, ratio)
	// Linear growth predicts 2x. Allow 50% scheduling/allocation noise (3x),
	// while rejecting the approximately 4x growth of a quadratic matcher.
	require.Less(t, ratio, 3.0, "filesystem matching must scale roughly linearly")
	ch := channels[1]
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

func TestFilesystemOverlappingMountsTiming(t *testing.T) {
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

func TestFilesystemOverlappingSourcesTiming(t *testing.T) {
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
