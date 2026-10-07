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
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

// Files are unchanged extractions of the pinned node_exporter's sys.ttar;
// golden.prom is its unchanged e2e-output.txt power_supply families, including
// invalid UTF-8 model_name replacement and the sparse AC info label set.
// All 11 fixture families are ported. The upstream emitter's other families
// have no fixture series: authentic, calibrate, capacity_alert_max/min,
// time_to_empty/full_seconds, current_boot/max/ampere, energy_empty/design,
// voltage_boot/max/max_design/min/ocv, charge_control_limit/max, charge_counter,
// charge_empty/design, charge_full/design, charge_ampere, charge_term_current,
// constant_charge_current/max, constant_charge_voltage/max, precharge_current,
// input_current_limit, and all eight temp_*_celsius families. These are tested
// separately below. charge_avg, current_avg, energy_avg, power_avg,
// time_to_empty_avg, time_to_full_avg and voltage_avg are parsed but not
// exported upstream; alarm, uevent and power/* are also not exported.
func TestPowersupplyConformance(t *testing.T) {
	c, err := newPowersupplyclassCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	families := []string{"capacity", "cyclecount", "energy_full", "energy_full_design", "energy_watthour", "info", "online", "power_watt", "present", "voltage_min_design", "voltage_volt"}
	for i := range families {
		families[i] = "node_power_supply_" + families[i]
	}
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/powersupplyclass", Expected: "testdata/powersupplyclass/golden.prom", Families: families})
}

func powersupplyFixture(t *testing.T) (*powersupplyclassCollector, agentless.Input) {
	t.Helper()
	collector, err := newPowersupplyclassCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	c := collector.(*powersupplyclassCollector)
	runner, err := agentlesstest.FromFS("testdata/powersupplyclass", nil, c.Reads())
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

func TestPowersupplyRegistrationAndBounds(t *testing.T) {
	built, err := Build([]string{"powersupplyclass"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Contains(t, DefaultEnabled(), "powersupplyclass")
	found := false
	for _, r := range Registered() {
		if r.Name == "powersupplyclass" {
			found = true
			require.Equal(t, "linux", r.OS)
			require.True(t, r.DefaultEnabled)
		}
	}
	require.True(t, found)
	c, in := powersupplyFixture(t)
	require.Equal(t, []agentless.Read{agentless.CommandRead("ls", "-1", "/sys/class/power_supply")}, c.Reads())
	require.NoError(t, c.Reads()[0].Validate())
	reads, err := c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	require.Len(t, reads, 120)
	seen := map[string]bool{}
	for _, read := range reads {
		require.NoError(t, read.Validate())
		require.Empty(t, read.Argv)
		require.False(t, seen[read.ID])
		seen[read.ID] = true
	}
	listing := c.Reads()[0]
	maxSupplies := agentless.MaxExpandedReads / powersupplyAttributes
	for _, count := range []int{5, maxSupplies, maxSupplies + 1, agentless.MaxExpandedReads + 1} {
		var output strings.Builder
		for i := 0; i < count; i++ {
			fmt.Fprintf(&output, "BAT%d\n", i)
		}
		in[listing.ID] = agentless.Result{Read: listing, Output: []byte(output.String())}
		reads, err := c.Expand(agentless.Target{}, in)
		if count <= maxSupplies {
			require.NoError(t, err)
			require.Len(t, reads, count*powersupplyAttributes)
			values := powersupplyScrape(t, c, in)
			require.Equal(t, 1.0, values["powersupplyclass"])
			require.Equal(t, float64(count), values["node_power_supply_info"])
			for _, read := range reads {
				require.NoError(t, read.Validate())
			}
		} else {
			require.ErrorContains(t, err, "expanded read limit")
			require.Nil(t, reads, "reject the whole expansion, never truncate")
			ch := make(chan prometheus.Metric, agentless.MaxExpandedReads)
			require.Error(t, c.Update(agentless.Target{}, in, ch))
			require.Empty(t, ch)
		}
	}
	for _, output := range []string{"\n", "BAT0", "BAT0\n\n", "BAT0\nBAT0\n", strings.Repeat("bad name\n", agentless.MaxExpandedReads+1), strings.Repeat("x", 1<<20) + "\n"} {
		in[listing.ID] = agentless.Result{Read: listing, Output: []byte(output)}
		reads, err := c.Expand(agentless.Target{}, in)
		require.Error(t, err)
		require.Nil(t, reads)
		ch := make(chan prometheus.Metric, 300)
		require.Error(t, c.Update(agentless.Target{}, in, ch))
		require.Empty(t, ch)
	}
	// Count even invalid rows: the exact shared cap fits, cap+1 above fails.
	in[listing.ID] = agentless.Result{Read: listing, Output: []byte(strings.Repeat("bad name\n", agentless.MaxExpandedReads))}
	reads, err = c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	require.Empty(t, reads)
	ch := make(chan prometheus.Metric, agentless.MaxExpandedReads)
	require.NoError(t, c.Update(agentless.Target{}, in, ch))
	require.Empty(t, ch)
	in[listing.ID] = agentless.Result{Read: listing, Output: []byte("BAT0\nbad name\n../evil\nx/y\n.\nx..y\nx;id\nx\x00y\nBAT0:1\n")}
	reads, err = c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	require.Len(t, reads, 60)
	for _, read := range reads {
		require.NoError(t, read.Validate())
		require.True(t, strings.HasPrefix(read.Path, "/sys/class/power_supply/BAT0/"))
	}
}

func TestPowersupplyAllNumericAttributes(t *testing.T) {
	c, in := powersupplyFixture(t)
	for _, spec := range powersupplyNumbers {
		read := powersupplyRead("BAT0", spec.attribute)
		in[read.ID] = agentless.Result{Read: read, Output: []byte("-1234567\n")}
	}
	ch := make(chan prometheus.Metric, 300)
	require.NoError(t, c.Update(agentless.Target{}, in, ch))
	close(ch)
	values := map[string]float64{}
	for metric := range ch {
		// Descriptor identifies the actual emitted family, not table order.
		var m dto.Metric
		require.NoError(t, metric.Write(&m))
		if len(m.Label) == 1 && m.Label[0].GetValue() == "BAT0" {
			for _, spec := range powersupplyNumbers {
				if strings.Contains(metric.Desc().String(), "fqName: \"node_power_supply_"+spec.family+"\"") {
					values[spec.family] = m.GetGauge().GetValue()
				}
			}
		}
	}
	require.Len(t, values, 49)
	for _, spec := range powersupplyNumbers {
		require.Equal(t, -1234567/spec.divisor, values[spec.family], spec.attribute)
	}
}

func TestPowersupplyScraperIsolation(t *testing.T) {
	var oversized strings.Builder
	for i := 0; i <= agentless.MaxExpandedReads/powersupplyAttributes; i++ {
		fmt.Fprintf(&oversized, "BAT%d\n", i)
	}
	cases := map[string]agentless.Result{
		"missing": {NotExist: true, ExitStatus: 1}, "empty": {}, "nonzero": {ExitStatus: 2, Output: []byte("BAT0\n")},
		"timeout": {TimedOut: true}, "truncated": {Truncated: true}, "missing timeout": {NotExist: true, TimedOut: true}, "missing truncated": {NotExist: true, Truncated: true},
		"malformed": {Output: []byte("BAT0\n\n")}, "oversized": {Output: []byte(oversized.String())},
	}
	for name, failure := range cases {
		t.Run(name, func(t *testing.T) {
			c, in := powersupplyFixture(t)
			read := c.Reads()[0]
			failure.Read = read
			in[read.ID] = failure
			families := powersupplyScrape(t, c, in)
			require.Zero(t, families["node_power_supply_info"])
			want := 0.0
			if name == "missing" || name == "empty" {
				want = 1
			}
			require.Equal(t, want, families["powersupplyclass"])
		})
	}
	for _, attribute := range []string{"capacity", "model_name"} {
		for name, failure := range map[string]agentless.Result{"missing": {NotExist: true, ExitStatus: 1}, "error": {ExitStatus: 1}, "timeout": {TimedOut: true}, "truncated": {Truncated: true}, "missing timeout": {NotExist: true, TimedOut: true}} {
			t.Run(attribute+"/"+name, func(t *testing.T) {
				c, in := powersupplyFixture(t)
				read := powersupplyRead("BAT0", attribute)
				failure.Read = read
				failure.Output = []byte("81\n")
				in[read.ID] = failure
				values := powersupplyScrape(t, c, in)
				if name == "missing" {
					require.Equal(t, 1.0, values["powersupplyclass"])
					require.Equal(t, 2.0, values["node_power_supply_info"])
					if attribute == "capacity" {
						require.Zero(t, values["node_power_supply_capacity"])
					}
				} else {
					require.Zero(t, values["powersupplyclass"])
					require.Zero(t, values["node_power_supply_info"])
				}
			})
		}
	}
}

func TestPowersupplyMalformedAttributeIsolated(t *testing.T) {
	for _, raw := range []string{"garbage", "9223372036854775808", strings.Repeat("1", 1<<20)} {
		c, in := powersupplyFixture(t)
		read := powersupplyRead("BAT0", "capacity")
		in[read.ID] = agentless.Result{Read: read, Output: []byte(raw)}
		values := powersupplyScrape(t, c, in)
		require.Equal(t, 1.0, values["powersupplyclass"])
		require.Zero(t, values["node_power_supply_capacity"])
		require.Equal(t, 2.0, values["node_power_supply_info"])
		require.Equal(t, 1.0, values["node_power_supply_energy_full"])
	}
	c, in := powersupplyFixture(t)
	read := powersupplyRead("BAT0", "model_name")
	in[read.ID] = agentless.Result{Read: read, Output: []byte(strings.Repeat("x", 1<<20))}
	values := powersupplyScrape(t, c, in)
	require.Equal(t, 1.0, values["powersupplyclass"])
	require.Equal(t, 2.0, values["node_power_supply_info"])
}

// Drive the real two-phase Scraper with the recorded filesystem fixture and
// verify that a failing powersupply collector never affects loadavg.
func powersupplyScrape(t *testing.T, c *powersupplyclassCollector, in agentless.Input) map[string]float64 {
	t.Helper()
	load := &loadavgCollector{}
	read := load.Reads()[0]
	in[read.ID] = agentless.Result{Read: read, Output: []byte("1 2 3 1/1 1\n")}
	scraper, err := agentless.NewScraper(&agentlesstest.FakeRunner{Results: in}, []agentless.Collector{c, load}, nil)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := scraper.Scrape(ctx, agentless.Target{})
	require.NoError(t, err)
	reg := prometheus.NewRegistry()
	reg.MustRegister(result)
	families, err := reg.Gather()
	require.NoError(t, err)
	values := map[string]float64{}
	for _, family := range families {
		values[family.GetName()] = float64(len(family.Metric))
		if family.GetName() == "node_scrape_collector_success" {
			for _, metric := range family.Metric {
				values[metric.Label[0].GetValue()] = metric.GetGauge().GetValue()
			}
		}
	}
	require.Equal(t, 1.0, values["loadavg"])
	require.Equal(t, 1.0, values["node_load1"])
	return values
}
