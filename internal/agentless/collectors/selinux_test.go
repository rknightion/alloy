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

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// The pinned exporter has no SELinux fixtures or e2e families. These authored
// fixtures exercise its three descriptors and go-selinux's 1/0/-1 mode mapping.
// No upstream default families are omitted; disabled emits only enabled.
func TestSELinuxConformance(t *testing.T) {
	for _, mode := range []string{"enforcing", "permissive", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			c, err := newSELinuxCollector(DefaultConfigs(), nil)
			require.NoError(t, err)
			families := []string{"node_selinux_enabled"}
			if mode != "disabled" {
				families = append(families, "node_selinux_config_mode", "node_selinux_current_mode")
			}
			root := "testdata/selinux/" + mode
			conformance.Check(t, conformance.Case{Collector: c, Root: root, Expected: root + "/golden.prom", Families: families})
		})
	}
}

func selinuxFixture(t *testing.T) (agentless.Collector, agentless.Input) {
	t.Helper()
	c, err := newSELinuxCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	in := agentless.Input{}
	for _, read := range c.Reads() {
		data, err := os.ReadFile("testdata/selinux/enforcing" + read.Path)
		require.NoError(t, err)
		in[read.ID] = agentless.Result{Read: read, Output: data}
	}
	return c, in
}

func TestSELinuxRegistrationAndReads(t *testing.T) {
	built, err := Build([]string{"selinux"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Equal(t, "selinux", built[0].Name())
	require.NotContains(t, DefaultEnabled(), "selinux")
	found := false
	for _, r := range Registered() {
		if r.Name == "selinux" {
			found = true
			require.Equal(t, "linux", r.OS)
			require.False(t, r.DefaultEnabled)
		}
	}
	require.True(t, found)
	require.Equal(t, []agentless.Read{agentless.FileRead("/proc/self/mountinfo"), agentless.FileRead("/sys/fs/selinux/enforce"), agentless.FileRead("/etc/selinux/config")}, built[0].Reads())
	for _, read := range built[0].Reads() {
		require.NoError(t, read.Validate())
	}
}

func TestSELinuxReadFailures(t *testing.T) {
	for index := range 3 {
		for name, result := range map[string]agentless.Result{
			"missing": {NotExist: true, ExitStatus: 1}, "nonzero": {ExitStatus: 2}, "timeout": {TimedOut: true}, "truncated": {Truncated: true}, "missing timeout": {NotExist: true, TimedOut: true}, "missing truncated": {NotExist: true, Truncated: true},
		} {
			t.Run(fmt.Sprintf("%d/%s", index, name), func(t *testing.T) {
				c, in := selinuxFixture(t)
				read := c.Reads()[index]
				result.Read = read
				result.Output = in[read.ID].Output
				in[read.ID] = result
				ch := make(chan prometheus.Metric, 3)
				err := c.Update(agentless.Target{}, in, ch)
				if name == "missing" {
					require.NoError(t, err)
					if index == 0 {
						require.Len(t, ch, 1)
					} else {
						require.Len(t, ch, 3)
					}
				} else {
					require.Error(t, err)
					require.Empty(t, ch)
				}
			})
		}
	}
	c, _ := selinuxFixture(t)
	require.Error(t, c.Update(agentless.Target{}, agentless.Input{}, make(chan prometheus.Metric, 3)))
}

func TestSELinuxBoundedParsing(t *testing.T) {
	for _, output := range []string{"SELINUX=bogus\n", "SELINUX=enforcing\nSELINUX=permissive\n", "bad", "SELINUX=", strings.Repeat("#\n", 1025), strings.Repeat("x", 4096), strings.Repeat("x", 1<<20)} {
		_, err := parseSELinuxConfig([]byte(output))
		require.Error(t, err)
	}
	for _, output := range []string{"", "garbage", strings.Repeat("x", 65536), strings.Repeat("x", 5<<20), "1 2 0:1 / / rw - selinuxfs selinuxfs " + strings.Repeat("x", 4097)} {
		_, err := parseSELinuxMounts([]byte(output))
		require.Error(t, err)
	}
	for _, output := range [][]byte{[]byte(strings.Repeat("x", 1<<20)), []byte(strings.Repeat("#\n", 1000000))} {
		allocs := testing.AllocsPerRun(3, func() { _, err := parseSELinuxConfig(output); require.Error(t, err) })
		require.Less(t, allocs, 10.0, "reject before input-sized retention")
	}
	for input, want := range map[string]int{"": -1, "# comment\nSELINUXTYPE=targeted\n": -1, "SELINUX=\"enforcing\"\n": 1, "SELINUX=permissive\n": 0, "SELINUX=disabled\n": -1} {
		value, err := parseSELinuxConfig([]byte(input))
		require.NoError(t, err)
		require.Equal(t, want, value)
	}
	enabled, err := parseSELinuxMounts([]byte("22 18 0:19 / /sys/fs/selinux ro - selinuxfs selinuxfs ro\n"))
	require.NoError(t, err)
	require.False(t, enabled)
	// A mount source may itself be "-"; only the first separator is structural.
	enabled, err = parseSELinuxMounts([]byte("22 18 0:19 / /sys/fs/selinux rw - selinuxfs - rw\n"))
	require.NoError(t, err)
	require.True(t, enabled)
}

func TestSELinuxScraperIsolation(t *testing.T) {
	for _, mode := range []string{"malformed", "oversized", "nonzero", "enforce", "missing"} {
		t.Run(mode, func(t *testing.T) {
			c, in := selinuxFixture(t)
			read := c.Reads()[2]
			bad := in[read.ID]
			switch mode {
			case "malformed":
				bad.Output = []byte("SELINUX=bogus\n")
			case "oversized":
				bad.Output = []byte(strings.Repeat("x", 1<<20))
			case "nonzero":
				bad.ExitStatus = 2
			case "enforce":
				read = c.Reads()[1]
				bad = in[read.ID]
				bad.Output = []byte("2")
			case "missing":
				read = c.Reads()[0]
				bad = in[read.ID]
				bad.NotExist = true
				bad.ExitStatus = 1
			}
			in[read.ID] = bad
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
			success := map[string]float64{}
			seenLoad, seenEnabled := false, false
			for _, family := range families {
				if strings.HasPrefix(family.GetName(), "node_selinux_") {
					require.Equal(t, "missing", mode)
					require.Equal(t, "node_selinux_enabled", family.GetName())
					require.Zero(t, family.Metric[0].GetGauge().GetValue())
					seenEnabled = true
				}
				if family.GetName() == "node_load1" {
					seenLoad = true
					require.Equal(t, 1.0, family.Metric[0].GetGauge().GetValue())
				}
				if family.GetName() == "node_scrape_collector_success" {
					for _, metric := range family.Metric {
						success[metric.Label[0].GetValue()] = metric.GetGauge().GetValue()
					}
				}
			}
			require.True(t, seenLoad)
			require.Equal(t, 1.0, success["loadavg"])
			want := 0.0
			if mode == "missing" {
				want = 1
				require.True(t, seenEnabled)
			}
			require.Equal(t, want, success["selinux"])
		})
	}
}
