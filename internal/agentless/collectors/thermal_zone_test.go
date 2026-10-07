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

// Files are unchanged sys.ttar thermal attributes from the root go.mod's
// pinned node_exporter (class symlinks materialized). All three exported
// families are checked against its e2e output; none is left out. Policy and
// mode are read but not exported upstream; passive is also not exported.
func TestThermalZoneConformance(t *testing.T) {
	c, err := newThermalZoneCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/thermal_zone", Families: []string{"node_thermal_zone_temp", "node_cooling_device_cur_state", "node_cooling_device_max_state"}})
}
func thermalFixture(t *testing.T) (*thermalZoneCollector, agentless.Input) {
	t.Helper()
	collector, err := newThermalZoneCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	c := collector.(*thermalZoneCollector)
	runner, err := agentlesstest.FromFS("testdata/thermal_zone", nil, c.Reads())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	in := agentless.Input{}
	results, err := runner.Run(ctx, agentless.Target{}, c.Reads())
	require.NoError(t, err)
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
func TestThermalZoneRegistration(t *testing.T) {
	built, err := Build([]string{"thermal_zone"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Equal(t, "thermal_zone", built[0].Name())
	require.NotContains(t, DefaultEnabled(), "thermal_zone")
	found := false
	for _, r := range Registered() {
		if r.Name == "thermal_zone" {
			found = true
			require.Equal(t, "linux", r.OS)
			require.False(t, r.DefaultEnabled)
		}
	}
	require.True(t, found)
	c, in := thermalFixture(t)
	require.Equal(t, []agentless.Read{agentless.CommandRead("ls", "-1", "/sys/class/thermal")}, c.Reads())
	require.NoError(t, c.Reads()[0].Validate())
	reads, err := c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	require.Len(t, reads, 7)
	seen := map[string]bool{}
	for _, r := range reads {
		require.NoError(t, r.Validate())
		require.Empty(t, r.Argv)
		require.False(t, seen[r.ID])
		seen[r.ID] = true
	}
}
func TestThermalZoneListingBounds(t *testing.T) {
	c, in := thermalFixture(t)
	listing := c.Reads()[0]
	for _, test := range []struct {
		output string
		count  int
		bad    bool
	}{
		{"thermal_zone0\ncooling_device0\n../evil\nthermal_zone1/x\nthermal_zone-1\nthermal_zone1;id\nthermal_zone\n", 7, false},
		{"thermal_zone0", 0, true}, {"\n", 0, true}, {"thermal_zone0\nthermal_zone0\n", 0, true},
		{strings.Repeat("invalid\n", 257), 0, true}, {strings.Repeat("x", 1<<20) + "\n", 0, true},
	} {
		in[listing.ID] = agentless.Result{Read: listing, Output: []byte(test.output)}
		reads, err := c.Expand(agentless.Target{}, in)
		if test.bad {
			require.Error(t, err)
			require.Nil(t, reads)
		} else {
			require.NoError(t, err)
			require.Len(t, reads, test.count)
		}
	}
	for _, count := range []int{64, 65} {
		var output strings.Builder
		for i := 0; i < count; i++ {
			fmt.Fprintf(&output, "thermal_zone%d\n", i)
		}
		in[listing.ID] = agentless.Result{Read: listing, Output: []byte(output.String())}
		reads, err := c.Expand(agentless.Target{}, in)
		if count == 64 {
			require.NoError(t, err)
			require.Len(t, reads, 256)
		} else {
			require.ErrorContains(t, err, "expanded read limit")
			require.Nil(t, reads)
		}
	}
}
func TestThermalZoneMalformedAttributeIsolated(t *testing.T) {
	for _, test := range []struct {
		device, attribute, output string
		want                      int
	}{
		{"thermal_zone0", "temp", "bad", 2}, {"thermal_zone0", "temp", strings.Repeat("1", 1<<20), 2},
		{"thermal_zone0", "temp", "9223372036854775808", 2}, {"thermal_zone0", "type", "\xff", 2},
		{"thermal_zone0", "type", strings.Repeat("x", 4097), 2}, {"cooling_device0", "cur_state", "NaN", 2},
		{"cooling_device0", "max_state", "bad", 2}, {"thermal_zone0", "policy", strings.Repeat("x", 1<<20), 3},
		{"thermal_zone0", "mode", "invalid", 3},
	} {
		t.Run(test.device+test.attribute+fmt.Sprint(len(test.output)), func(t *testing.T) {
			c, in := thermalFixture(t)
			r := thermalRead(test.device, test.attribute)
			in[r.ID] = agentless.Result{Read: r, Output: []byte(test.output)}
			ch := make(chan prometheus.Metric, 300)
			require.NoError(t, c.Update(agentless.Target{}, in, ch))
			require.Len(t, ch, test.want)
		})
	}
	c, in := thermalFixture(t)
	r := thermalRead("cooling_device0", "cur_state")
	in[r.ID] = agentless.Result{Read: r, Output: []byte("-1\n")}
	ch := make(chan prometheus.Metric, 300)
	require.NoError(t, c.Update(agentless.Target{}, in, ch))
	require.Len(t, ch, 3)
}
func TestThermalZoneScraperIsolation(t *testing.T) {
	for _, location := range []string{"listing", "attribute"} {
		for _, failure := range []struct {
			name    string
			result  agentless.Result
			success float64
			metrics int
		}{
			{"missing", agentless.Result{NotExist: true, ExitStatus: 1}, 1, 0},
			{"exit", agentless.Result{ExitStatus: 2}, 0, 0}, {"timeout", agentless.Result{TimedOut: true}, 0, 0},
			{"truncated", agentless.Result{Truncated: true}, 0, 0}, {"missing timeout", agentless.Result{NotExist: true, TimedOut: true}, 0, 0},
		} {
			t.Run(location+failure.name, func(t *testing.T) {
				c, in := thermalFixture(t)
				r := c.Reads()[0]
				if location == "attribute" {
					r = thermalRead("thermal_zone0", "temp")
				}
				result := failure.result
				result.Read = r
				result.Output = []byte("12376\n")
				in[r.ID] = result
				load := &loadavgCollector{}
				lr := load.Reads()[0]
				in[lr.ID] = agentless.Result{Read: lr, Output: []byte("1 2 3 1/1 1\n")}
				scraper, err := agentless.NewScraper(&agentlesstest.FakeRunner{Results: in}, []agentless.Collector{c, load}, nil)
				require.NoError(t, err)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				scraped, err := scraper.Scrape(ctx, agentless.Target{})
				require.NoError(t, err)
				reg := prometheus.NewRegistry()
				reg.MustRegister(scraped)
				families, err := reg.Gather()
				require.NoError(t, err)
				success := map[string]float64{}
				thermalCount := 0
				loadSeen := false
				for _, f := range families {
					if f.GetName() == "node_load1" {
						loadSeen = true
					}
					if strings.HasPrefix(f.GetName(), "node_thermal_") || strings.HasPrefix(f.GetName(), "node_cooling_") {
						thermalCount += len(f.Metric)
					}
					if f.GetName() == "node_scrape_collector_success" {
						for _, m := range f.Metric {
							success[m.Label[0].GetValue()] = m.GetGauge().GetValue()
						}
					}
				}
				require.True(t, loadSeen)
				require.Equal(t, 1.0, success["loadavg"])
				require.Equal(t, failure.success, success["thermal_zone"])
				want := failure.metrics
				if location == "attribute" && failure.name == "missing" {
					want = 2
				}
				require.Equal(t, want, thermalCount)
			})
		}
	}
}
