package collectors

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// Fixtures are unchanged extractions of collector/fixtures/sys.ttar and
// e2e-output.txt from node_exporter v0.18.1-grafana-r01.0.20251024135609-318b01780c89.
// All 15 emitted families are ported; none is intentionally omitted. The e2e
// oracle has 14: dumped_frames_total is absent because its fixture value is
// maxUint64 (firmware's unsupported sentinel). Its positive path is tested
// separately. Upstream's unused name/speed/port_state/port_type/symbolic_name/
// node_name/port_id/port_name/fabric_name/dev_loss_tmo/supported_classes/
// supported_speeds descriptors never emit standalone families.
func TestFibrechannelConformance(t *testing.T) {
	c, err := newFibrechannelCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	families := []string{"node_fibrechannel_info"}
	for _, spec := range fibrechannelCounters {
		if spec.attribute != "dumped_frames" {
			families = append(families, "node_fibrechannel_"+spec.family)
		}
	}
	require.Len(t, families, 14)
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/fibrechannel", Expected: "testdata/fibrechannel/golden.prom", Families: families})
}

func fibrechannelFixture(t *testing.T) (*fibrechannelCollector, agentless.Input) {
	t.Helper()
	collector, err := newFibrechannelCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	c := collector.(*fibrechannelCollector)
	runner, err := agentlesstest.FromFS("testdata/fibrechannel", nil, c.Reads())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results, err := runner.Run(ctx, agentless.Target{}, c.Reads())
	require.NoError(t, err)
	in := agentless.Input{}
	for _, result := range results {
		in[result.Read.ID] = result
	}
	reads, err := c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	results, err = runner.Run(ctx, agentless.Target{}, reads)
	require.NoError(t, err)
	for _, result := range results {
		in[result.Read.ID] = result
	}
	return c, in
}

func TestFibrechannelRegistrationAndReads(t *testing.T) {
	built, err := Build([]string{"fibrechannel"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Equal(t, "fibrechannel", built[0].Name())
	require.Contains(t, DefaultEnabled(), "fibrechannel")
	found := false
	for _, registration := range Registered() {
		if registration.Name == "fibrechannel" {
			found = true
			require.Equal(t, "linux", registration.OS)
			require.True(t, registration.DefaultEnabled)
		}
	}
	require.True(t, found)
	require.Equal(t, []agentless.Read{agentless.CommandRead("ls", "-1", "/sys/class/fc_host")}, built[0].Reads())
	require.NoError(t, built[0].Reads()[0].Validate())
	c, in := fibrechannelFixture(t)
	reads, err := c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	require.Len(t, reads, 25)
	seen := map[string]bool{}
	for _, read := range reads {
		require.NoError(t, read.Validate())
		require.Empty(t, read.Argv)
		require.False(t, seen[read.ID])
		seen[read.ID] = true
	}
}

func TestFibrechannelListingBounds(t *testing.T) {
	c, in := fibrechannelFixture(t)
	listing := c.Reads()[0]
	in[listing.ID] = agentless.Result{Read: listing, Output: []byte("host0\nbad name\n../evil\nx/y\n.\nx..y\nx;id\nx\x00y\nhost:1\nhost1\n")}
	reads, err := c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	require.Len(t, reads, 50)
	for _, read := range reads {
		require.NoError(t, read.Validate())
		require.True(t, strings.HasPrefix(read.Path, "/sys/class/fc_host/host0/") || strings.HasPrefix(read.Path, "/sys/class/fc_host/host1/"))
	}
	for _, count := range []int{40, 41} {
		var output strings.Builder
		for i := 0; i < count; i++ {
			fmt.Fprintf(&output, "host%d\n", i)
		}
		in[listing.ID] = agentless.Result{Read: listing, Output: []byte(output.String())}
		reads, err := c.Expand(agentless.Target{}, in)
		if count == 40 {
			require.NoError(t, err)
			require.Len(t, reads, 1000)
		} else {
			require.ErrorContains(t, err, "expanded read limit")
			require.Nil(t, reads, "reject the whole expansion")
		}
	}
	for _, output := range []string{"\n", "host0", "host0\n\n", "host0\nhost0\n", strings.Repeat("bad name\n", 1025), strings.Repeat("x", 4097) + "\n", strings.Repeat("x", 1<<20) + "\n"} {
		in[listing.ID] = agentless.Result{Read: listing, Output: []byte(output)}
		reads, err := c.Expand(agentless.Target{}, in)
		require.Error(t, err)
		require.Nil(t, reads)
		ch := make(chan prometheus.Metric, 600)
		require.Error(t, c.Update(agentless.Target{}, in, ch))
		require.Empty(t, ch)
	}
	for _, output := range []string{strings.Repeat("bad name\n", 1024), strings.Repeat("x", 4096) + "\n"} {
		in[listing.ID] = agentless.Result{Read: listing, Output: []byte(output)}
		reads, err := c.Expand(agentless.Target{}, in)
		require.NoError(t, err)
		if strings.HasPrefix(output, "x") {
			require.Len(t, reads, 25)
		} else {
			require.Empty(t, reads)
		}
	}
}

type fibrechannelMetrics struct {
	c  *fibrechannelCollector
	in agentless.Input
}

func (fibrechannelMetrics) Describe(chan<- *prometheus.Desc) {}
func (c fibrechannelMetrics) Collect(ch chan<- prometheus.Metric) {
	if err := c.c.Update(agentless.Target{}, c.in, ch); err != nil {
		ch <- prometheus.NewInvalidMetric(prometheus.NewDesc("fibrechannel_test_error", "Update failed.", nil, nil), err)
	}
}

func TestFibrechannelCounterValues(t *testing.T) {
	for _, output := range []string{"0", "42", "0x2a", "18446744073709551614", "18446744073709551615", "0xffffffffffffffff"} {
		c, in := fibrechannelFixture(t)
		read := fibrechannelRead("host0", "statistics/dumped_frames")
		in[read.ID] = agentless.Result{Read: read, Output: []byte(output + "\n")}
		want := ""
		switch output {
		case "0":
			want = "0"
		case "42", "0x2a":
			want = "42"
		case "18446744073709551614":
			want = "1.8446744073709552e+19"
		}
		expected := ""
		if want != "" {
			expected = "# HELP node_fibrechannel_dumped_frames_total Number of dumped frames\n# TYPE node_fibrechannel_dumped_frames_total counter\nnode_fibrechannel_dumped_frames_total{fc_host=\"host0\"} " + want + "\n"
		}
		require.NoError(t, testutil.CollectAndCompare(fibrechannelMetrics{c, in}, strings.NewReader(expected), "node_fibrechannel_dumped_frames_total"))
	}
}

func TestFibrechannelAttributeBounds(t *testing.T) {
	for _, test := range []struct{ attribute, output string }{
		{"symbolic_name", strings.Repeat("x", 4097)}, {"node_name", strings.Repeat("x", 4097)}, {"speed", "\xff"},
		{"statistics/rx_frames", "bad"}, {"statistics/rx_frames", "-1"}, {"statistics/rx_frames", "18446744073709551616"},
		{"statistics/rx_frames", strings.Repeat("1", 1<<20)}, {"symbolic_name", strings.Repeat(" ", 1<<20) + "x"},
	} {
		c, in := fibrechannelFixture(t)
		read := fibrechannelRead("host0", test.attribute)
		in[read.ID] = agentless.Result{Read: read, Output: []byte(test.output)}
		ch := make(chan prometheus.Metric, 600)
		require.Error(t, c.Update(agentless.Target{}, in, ch))
		require.Empty(t, ch, "no partial host metrics")
	}
	c, in := fibrechannelFixture(t)
	read := fibrechannelRead("host0", "symbolic_name")
	in[read.ID] = agentless.Result{Read: read, Output: []byte(strings.Repeat("x", 4096) + "\n")}
	reg := prometheus.NewRegistry()
	reg.MustRegister(fibrechannelMetrics{c, in})
	families, err := reg.Gather()
	require.NoError(t, err)
	require.Len(t, families, 14)
	for _, family := range families {
		if family.GetName() == "node_fibrechannel_info" {
			found := false
			for _, label := range family.Metric[0].Label {
				if label.GetName() == "symbolic_name" {
					found = true
					require.Len(t, label.GetValue(), 4096)
				}
			}
			require.True(t, found)
		}
	}
}

type fibrechannelRecordingRunner struct {
	fake    *agentlesstest.FakeRunner
	batches [][]agentless.Read
}

func (r *fibrechannelRecordingRunner) Run(ctx context.Context, target agentless.Target, reads []agentless.Read) ([]agentless.Result, error) {
	r.batches = append(r.batches, append([]agentless.Read(nil), reads...))
	return r.fake.Run(ctx, target, reads)
}

func TestFibrechannelScraperIsolation(t *testing.T) {
	var oversized strings.Builder
	for i := 0; i < 41; i++ {
		fmt.Fprintf(&oversized, "host%d\n", i)
	}
	cases := []struct {
		name, attribute   string
		result            agentless.Result
		ok                bool
		families, batches int
	}{
		{"missing listing", "", agentless.Result{NotExist: true, ExitStatus: 1}, true, 0, 1},
		{"empty listing", "", agentless.Result{}, true, 0, 1},
		{"nonzero listing", "", agentless.Result{ExitStatus: 2, Output: []byte("host0\n")}, false, 0, 1},
		{"timeout listing", "", agentless.Result{TimedOut: true}, false, 0, 1},
		{"truncated listing", "", agentless.Result{Truncated: true}, false, 0, 1},
		{"missing timeout", "", agentless.Result{NotExist: true, TimedOut: true}, false, 0, 1},
		{"missing truncated", "", agentless.Result{NotExist: true, Truncated: true}, false, 0, 1},
		{"oversized listing", "", agentless.Result{Output: []byte(oversized.String())}, false, 0, 1},
		{"too many invalid rows", "", agentless.Result{Output: []byte(strings.Repeat("bad name\n", 1025))}, false, 0, 1},
		{"malformed listing", "", agentless.Result{Output: []byte("host0\n\n")}, false, 0, 1},
		{"valid and invalid", "", agentless.Result{Output: []byte("host0\n../evil\nbad name\n")}, true, 14, 2},
		{"missing counter", "statistics/rx_frames", agentless.Result{NotExist: true, ExitStatus: 1, Output: []byte("42\n")}, true, 13, 2},
		{"missing string", "speed", agentless.Result{NotExist: true, ExitStatus: 1}, true, 14, 2},
		{"malformed counter", "statistics/rx_frames", agentless.Result{Output: []byte("bad\n")}, false, 0, 2},
		{"failed counter", "statistics/rx_frames", agentless.Result{ExitStatus: 2, Output: []byte("42\n")}, false, 0, 2},
		{"truncated counter", "statistics/rx_frames", agentless.Result{Truncated: true, Output: []byte("42\n")}, false, 0, 2},
		{"timed out counter", "statistics/rx_frames", agentless.Result{TimedOut: true}, false, 0, 2},
		{"failed string", "speed", agentless.Result{ExitStatus: 2}, false, 0, 2},
		{"missing truncated string", "speed", agentless.Result{NotExist: true, Truncated: true}, false, 0, 2},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			c, in := fibrechannelFixture(t)
			read := c.Reads()[0]
			if test.attribute != "" {
				read = fibrechannelRead("host0", test.attribute)
			}
			test.result.Read = read
			in[read.ID] = test.result
			load := &loadavgCollector{}
			lr := load.Reads()[0]
			in[lr.ID] = agentless.Result{Read: lr, Output: []byte("1 2 3 1/1 1\n")}
			runner := &fibrechannelRecordingRunner{fake: &agentlesstest.FakeRunner{Results: in}}
			scraper, err := agentless.NewScraper(runner, []agentless.Collector{c, load}, nil)
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
			loadSeen, fcFamilies := false, 0
			for _, family := range families {
				if family.GetName() == "node_load1" {
					loadSeen = true
					require.Equal(t, 1.0, family.Metric[0].GetGauge().GetValue())
				}
				if strings.HasPrefix(family.GetName(), "node_fibrechannel_") {
					fcFamilies++
					if test.name == "missing counter" {
						require.NotEqual(t, "node_fibrechannel_rx_frames_total", family.GetName())
					}
					if test.name == "missing string" && family.GetName() == "node_fibrechannel_info" {
						for _, label := range family.Metric[0].Label {
							if label.GetName() == "speed" {
								require.Empty(t, label.GetValue())
							}
						}
					}
				}
				if family.GetName() == "node_scrape_collector_success" {
					for _, metric := range family.Metric {
						success[metric.Label[0].GetValue()] = metric.GetGauge().GetValue()
					}
				}
			}
			require.True(t, loadSeen)
			require.Equal(t, 1.0, success["loadavg"])
			want := 0.0
			if test.ok {
				want = 1
			}
			require.Equal(t, want, success["fibrechannel"])
			require.Equal(t, test.families, fcFamilies)
			require.Len(t, runner.batches, test.batches)
			if test.batches == 2 {
				require.Len(t, runner.batches[1], 25)
				for _, read := range runner.batches[1] {
					require.NoError(t, read.Validate())
					require.True(t, strings.HasPrefix(read.Path, "/sys/class/fc_host/host0/"))
				}
			}
		})
	}
}
