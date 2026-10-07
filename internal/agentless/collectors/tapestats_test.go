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
	"github.com/stretchr/testify/require"
)

// Fixtures are unchanged st0 stats extracted from the pinned node_exporter's
// sys.ttar (class symlink materialized); golden.prom is its e2e-output.txt's
// tape families. All ten families are ported; none is omitted.
func TestTapestatsConformance(t *testing.T) {
	c, err := newTapestatsCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	var families []string
	for _, spec := range tapestatsAttributes {
		families = append(families, "node_tape_"+spec.family)
	}
	require.Len(t, families, 10)
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/tapestats", Expected: "testdata/tapestats/golden.prom", Families: families})
}
func tapestatsFixture(t *testing.T) (*tapestatsCollector, agentless.Input) {
	t.Helper()
	built, err := newTapestatsCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	c := built.(*tapestatsCollector)
	runner, err := agentlesstest.FromFS("testdata/tapestats", nil, c.Reads())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results, err := runner.Run(ctx, agentless.Target{}, c.Reads())
	require.NoError(t, err)
	in := agentless.Input{}
	for _, r := range results {
		in[r.Read.ID] = r
	}
	reads, err := c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	results, err = runner.Run(ctx, agentless.Target{}, reads)
	require.NoError(t, err)
	for _, r := range results {
		in[r.Read.ID] = r
	}
	return c, in
}
func TestTapestatsRegistration(t *testing.T) {
	built, err := Build([]string{"tapestats"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Equal(t, "tapestats", built[0].Name())
	require.NotContains(t, DefaultEnabled(), "tapestats")
	found := false
	for _, r := range Registered() {
		if r.Name == "tapestats" {
			found = true
			require.Equal(t, "linux", r.OS)
			require.False(t, r.DefaultEnabled)
		}
	}
	require.True(t, found)
	require.Equal(t, []agentless.Read{agentless.CommandRead("ls", "-1", "/sys/class/scsi_tape")}, built[0].Reads())
	require.NoError(t, built[0].Reads()[0].Validate())
}
func TestTapestatsListingBounds(t *testing.T) {
	c, in := tapestatsFixture(t)
	listing := c.Reads()[0]
	for _, count := range []int{102, 103} {
		var b strings.Builder
		for i := 0; i < count; i++ {
			fmt.Fprintf(&b, "st%d\n", i)
		}
		in[listing.ID] = agentless.Result{Read: listing, Output: []byte(b.String())}
		reads, err := c.Expand(agentless.Target{}, in)
		if count == 102 {
			require.NoError(t, err)
			require.Len(t, reads, 1020)
			for _, read := range reads {
				require.NoError(t, read.Validate())
				require.Empty(t, read.Argv)
			}
		} else {
			require.ErrorContains(t, err, "expanded read limit")
			require.Nil(t, reads)
		}
	}
	for _, output := range []string{"st0", "\n", "st0\n\n", "st0\nst0\n", strings.Repeat("nst0\n", 1025), strings.Repeat("x", 4097) + "\n"} {
		in[listing.ID] = agentless.Result{Read: listing, Output: []byte(output)}
		reads, err := c.Expand(agentless.Target{}, in)
		require.Error(t, err)
		require.Nil(t, reads)
	}
	for _, output := range []string{strings.Repeat("nst0\n", 1024), strings.Repeat("x", 4096) + "\n"} {
		in[listing.ID] = agentless.Result{Read: listing, Output: []byte(output)}
		reads, err := c.Expand(agentless.Target{}, in)
		require.NoError(t, err)
		require.Empty(t, reads)
	}
	in[listing.ID] = agentless.Result{Read: listing, Output: []byte("st0\nst0a\nnst0\nst\nst1/evil\nst2;id\n../st3\nst4\n")}
	reads, err := c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	require.Len(t, reads, 20)
	for _, r := range reads {
		require.NoError(t, r.Validate())
		require.True(t, strings.HasPrefix(r.Path, "/sys/class/scsi_tape/st0/") || strings.HasPrefix(r.Path, "/sys/class/scsi_tape/st4/"))
	}
}
func TestTapestatsAttributeBounds(t *testing.T) {
	for _, output := range []string{"bad", "-1", "18446744073709551616", strings.Repeat("1", 22), strings.Repeat(" ", 1<<20) + "1"} {
		c, in := tapestatsFixture(t)
		read := tapestatsRead("st0", "write_ns")
		in[read.ID] = agentless.Result{Read: read, Output: []byte(output)}
		ch := make(chan prometheus.Metric, 20)
		require.Error(t, c.Update(agentless.Target{}, in, ch))
		require.Empty(t, ch, "no partial metrics")
	}
	c, in := tapestatsFixture(t)
	read := tapestatsRead("st0", "in_flight")
	in[read.ID] = agentless.Result{Read: read, Output: []byte("18446744073709551615\n")}
	ch := make(chan prometheus.Metric, 20)
	require.NoError(t, c.Update(agentless.Target{}, in, ch))
	require.Len(t, ch, 10)
}

type tapestatsRunner struct {
	fake    *agentlesstest.FakeRunner
	batches [][]agentless.Read
}

func (r *tapestatsRunner) Run(ctx context.Context, target agentless.Target, reads []agentless.Read) ([]agentless.Result, error) {
	r.batches = append(r.batches, append([]agentless.Read(nil), reads...))
	return r.fake.Run(ctx, target, reads)
}
func TestTapestatsScraperIsolation(t *testing.T) {
	cases := map[string]agentless.Result{"missing": {NotExist: true, ExitStatus: 1}, "empty": {}, "error": {ExitStatus: 2}, "truncated": {Truncated: true}, "timeout": {TimedOut: true}, "missing timeout": {NotExist: true, TimedOut: true}, "missing truncated": {NotExist: true, Truncated: true}, "malformed": {Output: []byte("st0\n\n")}, "oversized": {Output: []byte(strings.Repeat("nst0\n", 1025))}}
	for name, failure := range cases {
		t.Run(name, func(t *testing.T) {
			c, in := tapestatsFixture(t)
			listing := c.Reads()[0]
			failure.Read = listing
			in[listing.ID] = failure
			tapestatsScrape(t, c, in, name == "missing" || name == "empty", 0, 1)
		})
	}
	for name, failure := range map[string]agentless.Result{"missing": {NotExist: true, ExitStatus: 1}, "error": {ExitStatus: 2}, "timeout": {TimedOut: true}, "truncated": {Truncated: true}, "malformed": {Output: []byte("bad")}, "oversized": {Output: []byte(strings.Repeat("1", 22))}} {
		t.Run("attribute "+name, func(t *testing.T) {
			c, in := tapestatsFixture(t)
			read := tapestatsRead("st0", "write_ns")
			failure.Read = read
			in[read.ID] = failure
			count := 0
			if name == "missing" {
				count = 9
			}
			tapestatsScrape(t, c, in, name == "missing", count, 2)
		})
	}
}
func tapestatsScrape(t *testing.T, c *tapestatsCollector, in agentless.Input, ok bool, count, batches int) {
	t.Helper()
	load := &loadavgCollector{}
	read := load.Reads()[0]
	in[read.ID] = agentless.Result{Read: read, Output: []byte("1 2 3 1/1 1\n")}
	runner := &tapestatsRunner{fake: &agentlesstest.FakeRunner{Results: in}}
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
	tape := 0
	loadSeen := false
	for _, f := range families {
		if strings.HasPrefix(f.GetName(), "node_tape_") {
			tape++
		}
		if f.GetName() == "node_load1" {
			loadSeen = true
		}
		if f.GetName() == "node_scrape_collector_success" {
			for _, m := range f.Metric {
				success[m.Label[0].GetValue()] = m.GetGauge().GetValue()
			}
		}
	}
	require.True(t, loadSeen)
	require.Equal(t, 1.0, success["loadavg"])
	want := 0.0
	if ok {
		want = 1
	}
	require.Equal(t, want, success["tapestats"])
	require.Equal(t, count, tape)
	require.Len(t, runner.batches, batches)
}

// Fill scrape capacity with unrelated, fixed reads so tape admission is tested
// at exactly 4096 and immediately beyond it through the real Scraper.
type tapestatsCapacity struct{ index, count int }

func (c tapestatsCapacity) Name() string          { return fmt.Sprintf("capacity%d", c.index) }
func (tapestatsCapacity) Reads() []agentless.Read { return nil }
func (c tapestatsCapacity) Expand(agentless.Target, agentless.Input) ([]agentless.Read, error) {
	reads := make([]agentless.Read, c.count)
	for i := range reads {
		reads[i] = agentless.FileRead(fmt.Sprintf("/capacity/%d/%d", c.index, i))
	}
	return reads, nil
}
func (tapestatsCapacity) Update(agentless.Target, agentless.Input, chan<- prometheus.Metric) error {
	return nil
}
func TestTapestatsScrapeCapacityBoundary(t *testing.T) {
	for _, last := range []int{1014, 1015} {
		t.Run(fmt.Sprint(last), func(t *testing.T) {
			c, in := tapestatsFixture(t)
			runner := &tapestatsRunner{fake: &agentlesstest.FakeRunner{Results: in}}
			collectors := []agentless.Collector{tapestatsCapacity{0, 1024}, tapestatsCapacity{1, 1024}, tapestatsCapacity{2, 1024}, tapestatsCapacity{3, last}, c}
			scraper, err := agentless.NewScraper(runner, collectors, nil)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := scraper.Scrape(ctx, agentless.Target{})
			require.NoError(t, err)
			reg := prometheus.NewRegistry()
			reg.MustRegister(result)
			families, err := reg.Gather()
			require.NoError(t, err)
			tape := 0
			success := -1.0
			for _, f := range families {
				if strings.HasPrefix(f.GetName(), "node_tape_") {
					tape++
				}
				if f.GetName() == "node_scrape_collector_success" {
					for _, m := range f.Metric {
						if m.Label[0].GetValue() == "tapestats" {
							success = m.GetGauge().GetValue()
						}
					}
				}
			}
			require.Len(t, runner.batches, 2)
			if last == 1014 {
				require.Len(t, runner.batches[1], 4096)
				require.Equal(t, 10, tape)
				require.Equal(t, 1.0, success)
			} else {
				require.Len(t, runner.batches[1], 4087)
				require.Zero(t, tape)
				require.Zero(t, success)
				for _, r := range runner.batches[1] {
					require.False(t, strings.HasPrefix(r.Path, "/sys/class/scsi_tape/"))
				}
			}
		})
	}
}
