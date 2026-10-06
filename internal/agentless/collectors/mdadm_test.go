package collectors

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/grafana/alloy/internal/agentless/conformance"
)

// Unchanged fixture and filtered golden from node_exporter
// v0.18.1-grafana-r01.0.20251024135609-318b01780c89/collector/fixtures.
// All five default families are owned; there are no omissions or sysfs reads.
func TestMdadmConformance(t *testing.T) {
	c, err := newMdadmCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	conformance.Check(t, conformance.Case{
		Collector: c, Root: "testdata/mdadm", Expected: "testdata/mdadm/golden.prom",
		Families: []string{"node_md_state", "node_md_disks", "node_md_disks_required", "node_md_blocks", "node_md_blocks_synced"},
	})
}

func mdadmFixture(t *testing.T) (agentless.Collector, agentless.Input) {
	t.Helper()
	c, err := newMdadmCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	output, err := os.ReadFile("testdata/mdadm/proc/mdstat")
	require.NoError(t, err)
	read := c.Reads()[0]
	return c, agentless.Input{read.ID: {Read: read, Output: output}}
}

func TestMdadmRegistrationAndReads(t *testing.T) {
	cs, err := Build([]string{"mdadm"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, cs, 1)
	require.Equal(t, "mdadm", cs[0].Name())
	require.NotContains(t, DefaultEnabled(), "mdadm")
	for _, r := range Registered() {
		if r.Name == "mdadm" {
			require.Equal(t, "linux", r.OS)
			require.False(t, r.DefaultEnabled)
		}
	}
	require.Equal(t, []agentless.Read{agentless.FileRead("/proc/mdstat")}, cs[0].Reads())
	require.NoError(t, cs[0].Reads()[0].Validate())
	require.Empty(t, cs[0].Reads()[0].Argv)
}

func TestMdadmReadFailures(t *testing.T) {
	for name, result := range map[string]agentless.Result{
		"nonzero": {ExitStatus: 2}, "truncated": {Truncated: true}, "timeout": {TimedOut: true},
		"missing truncated": {NotExist: true, Truncated: true}, "missing timeout": {NotExist: true, TimedOut: true},
	} {
		t.Run(name, func(t *testing.T) {
			c, in := mdadmFixture(t)
			in[c.Reads()[0].ID] = result
			ch := make(chan prometheus.Metric, 20000)
			require.Error(t, c.Update(agentless.Target{}, in, ch))
			require.Empty(t, ch)
		})
	}
	c, _ := mdadmFixture(t)
	require.Error(t, c.Update(agentless.Target{}, nil, make(chan prometheus.Metric, 20000)))
}

const mdadmTestHeader = "Personalities : [raid1] [raid0] [linear]\n"
const mdadmTestDevice = "md0 : active raid1 sda[0] sdb[1]\n  100 blocks [2/2] [UU]\n"

func TestMdadmMalformed(t *testing.T) {
	for i, output := range []string{
		"", "garbage", "Personalities : garbage\n", mdadmTestHeader + "\xff : active raid1\n  1 blocks [1/1] [U]\n", mdadmTestHeader + "md0", mdadmTestHeader + "md0 : active raid1\n",
		mdadmTestHeader + "md0 : active raid1\n  -1 blocks [2/2] [UU]\n",
		mdadmTestHeader + "md0 : active raid1\n  18446744073709551616 blocks [2/2] [UU]\n",
		mdadmTestHeader + "md0 : active raid1\n  1 blocks [2/3] [UU]\n",
		mdadmTestHeader + "md0 : active raid1\n  1 blocks [2/2] [U]\n",
		mdadmTestHeader + "md0 : broken raid1\n  100 blocks [2/2] [UU]\n",
		mdadmTestHeader + mdadmTestDevice + mdadmTestDevice,
		mdadmTestHeader + mdadmTestDevice + "  recovery = 1.0% (1/100) finish=1min\n",
		mdadmTestHeader + mdadmTestDevice + "  recovery = 1.0% (101/100) finish=1min speed=1K/sec\n",
		mdadmTestHeader + mdadmTestDevice + "  resync\n",
		mdadmTestHeader + mdadmTestDevice + "  bitmap: x\n  bitmap: y\n",
		mdadmTestHeader + mdadmTestDevice + "unknown tail\n",
		mdadmTestHeader + "m : active raid0\n  12 rubbish\n",
		mdadmTestHeader + strings.Repeat(" ", maxMdadmLineBytes) + "\n",
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			c, in := mdadmFixture(t)
			read := c.Reads()[0]
			in[read.ID] = agentless.Result{Read: read, Output: []byte(output)}
			ch := make(chan prometheus.Metric, 20000)
			require.Error(t, c.Update(agentless.Target{}, in, ch))
			require.Empty(t, ch, "atomic validation before emission")
		})
	}
}

func TestMdadmEmptyAndSyncStates(t *testing.T) {
	devices, err := parseMdadm([]byte("Personalities :\nunused devices: <none>\n"))
	require.NoError(t, err)
	require.Empty(t, devices)
	for _, state := range []struct {
		line   string
		state  int
		synced int64
	}{
		{"", 0, 100}, {"  recovery = 1.0% (1/100) finish=1min speed=1K/sec\n", 2, 1},
		{"  resync=PENDING\n", 3, 0}, {"  resync=DELAYED\n", 3, 0},
		{"  check = 1.0% (1/100) finish=1min speed=1K/sec\n", 4, 1},
	} {
		devices, err := parseMdadm([]byte(mdadmTestHeader + mdadmTestDevice + "  bitmap: 0/1 pages\n" + state.line))
		require.NoError(t, err)
		require.Len(t, devices, 1)
		require.Equal(t, state.state, devices[0].state)
		require.Equal(t, state.synced, devices[0].synced)
	}
}

func TestMdadmPreRetentionBounds(t *testing.T) {
	var b strings.Builder
	b.WriteString(mdadmTestHeader)
	for i := range maxMdadmDevices {
		fmt.Fprintf(&b, "md%d : active raid1 sda[0]\n  1 blocks [1/1] [U]\n", i)
	}
	atCap := []byte(b.String())
	devices, err := parseMdadm(atCap)
	require.NoError(t, err)
	require.Len(t, devices, maxMdadmDevices)
	c, in := mdadmFixture(t)
	read := c.Reads()[0]
	in[read.ID] = agentless.Result{Read: read, Output: atCap}
	ch := make(chan prometheus.Metric, 20000)
	require.NoError(t, c.Update(agentless.Target{}, in, ch))
	require.Len(t, ch, maxMdadmDevices*11)
	_, err = parseMdadm(append(atCap, []byte("extra : active raid1\n  1 blocks [1/1] [U]\n")...))
	require.ErrorContains(t, err, "device limit")
	for _, n := range []int{maxMdadmDeviceBytes, maxMdadmDeviceBytes + 1} {
		output := []byte(mdadmTestHeader + strings.Repeat("m", n) + " : active raid1\n  1 blocks [1/1] [U]\n")
		devices, err = parseMdadm(output)
		if n == maxMdadmDeviceBytes {
			require.NoError(t, err)
			require.Len(t, devices, 1)
		} else {
			require.Error(t, err)
			require.Empty(t, devices)
		}
	}
	// Blank hostile lines allocate no strings/slices per row. The scanner buffer
	// is fixed, so increasing line count cannot increase the allocation count.
	small := []byte(mdadmTestHeader + mdadmTestDevice)
	large := append(append([]byte{}, small...), []byte(strings.Repeat(" \t\n", 100000))...)
	measure := func(output []byte) float64 {
		return testing.AllocsPerRun(2, func() { _, err := parseMdadm(output); require.NoError(t, err) })
	}
	require.LessOrEqual(t, measure(large), measure(small)+2)
	_, err = parseMdadm(append(large, []byte("bad tail\n")...))
	require.Error(t, err)
	// Component count does not create a per-component retained slice.
	one := []byte(mdadmTestHeader + "md0 : active raid0 s[0]\n  1 blocks\n")
	many := []byte(mdadmTestHeader + "md0 : active raid0 " + strings.Repeat("s[0] ", 10000) + "\n  1 blocks\n")
	require.LessOrEqual(t, measure(many), measure(one)+2)
}

func TestMdadmScraperIsolation(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			c, in := mdadmFixture(t)
			read := c.Reads()[0]
			in[read.ID] = agentless.Result{Read: read, Output: []byte("malformed")}
			if missing {
				in[read.ID] = agentless.Result{Read: read, NotExist: true, ExitStatus: 1}
			}
			load := &loadavgCollector{}
			lr := load.Reads()[0]
			in[lr.ID] = agentless.Result{Read: lr, Output: []byte("1 2 3 1/1 1\n")}
			scraper, err := agentless.NewScraper(&agentlesstest.FakeRunner{Results: in}, []agentless.Collector{c, load}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := scraper.Scrape(ctx, agentless.Target{})
			require.NoError(t, err)
			reg := prometheus.NewRegistry()
			reg.MustRegister(result)
			families, err := reg.Gather()
			require.NoError(t, err)
			byName := map[string]*dto.MetricFamily{}
			for _, f := range families {
				byName[f.GetName()] = f
			}
			require.Equal(t, 1.0, byName["node_load1"].Metric[0].GetGauge().GetValue())
			success := map[string]float64{}
			for _, m := range byName["node_scrape_collector_success"].Metric {
				success[m.Label[0].GetValue()] = m.GetGauge().GetValue()
			}
			require.Equal(t, 1.0, success["loadavg"])
			want := 0.0
			if missing {
				want = 1
			}
			require.Equal(t, want, success["mdadm"])
			require.Nil(t, byName["node_md_blocks"])
		})
	}
}
