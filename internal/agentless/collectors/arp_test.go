package collectors

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// Fixture is unchanged from node_exporter
// v0.18.1-grafana-r01.0.20251024135609-318b01780c89. The golden runs its
// ARP collector with netlink and device filters disabled, so it includes
// the fixture's "nope" device (excluded by the upstream e2e invocation).
func TestARPConformance(t *testing.T) {
	c, err := newARPCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/arp", Expected: "testdata/arp/golden.prom", Families: []string{"node_arp_entries"}})
}

func TestARPRegistration(t *testing.T) {
	built, err := Build([]string{"arp"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Equal(t, "arp", built[0].Name())
	require.Contains(t, DefaultEnabled(), "arp")
	found := false
	for _, registration := range Registered() {
		if registration.Name == "arp" {
			found = true
			require.Equal(t, "linux", registration.OS)
			require.True(t, registration.DefaultEnabled)
		}
	}
	require.True(t, found)
	require.Equal(t, []agentless.Read{agentless.FileRead("/proc/net/arp")}, built[0].Reads())
	require.NoError(t, built[0].Reads()[0].Validate())
}

func TestARPReadFailures(t *testing.T) {
	c, err := newARPCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	read := c.Reads()[0]
	for name, result := range map[string]agentless.Result{
		"nonzero": {ExitStatus: 2}, "timeout": {TimedOut: true}, "truncated": {Truncated: true},
		"missing timeout": {NotExist: true, TimedOut: true}, "missing truncated": {NotExist: true, Truncated: true},
	} {
		t.Run(name, func(t *testing.T) {
			ch := make(chan prometheus.Metric, 1)
			require.Error(t, c.Update(agentless.Target{}, agentless.Input{read.ID: result}, ch))
			require.Empty(t, ch)
		})
	}
	require.Error(t, c.Update(agentless.Target{}, agentless.Input{}, make(chan prometheus.Metric, 1)))
	for _, result := range []agentless.Result{{NotExist: true, ExitStatus: 1}, {Output: []byte("")}, {Output: []byte("IP address HW type Flags HW address Mask Device\n")}} {
		ch := make(chan prometheus.Metric, 1)
		require.NoError(t, c.Update(agentless.Target{}, agentless.Input{read.ID: result}, ch))
		require.Empty(t, ch)
	}
}

func TestARPParsingAndBounds(t *testing.T) {
	row := func(device string) string { return "192.0.2.1 0x1 0x2 00:11:22:33:44:55 * " + device + "\n" }
	counts, err := parseARPCounts([]byte(row("eth0") + row("eth0") + row("eth1")))
	require.NoError(t, err)
	require.Equal(t, map[string]uint32{"eth0": 2, "eth1": 1}, counts)
	// Preserve procfs's ignored columns and accepted extended MAC formats.
	counts, err = parseARPCounts([]byte("ignored ignored 0xff 00:11:22:33:44:55:66:77 ignored eth0\n"))
	require.NoError(t, err)
	require.Equal(t, uint32(1), counts["eth0"])
	for _, device := range []string{strings.Repeat("x", 4096), string([]byte{0xff}), `"eth0`} {
		counts, err := parseARPCounts([]byte(row(device)))
		require.NoError(t, err)
		require.Equal(t, map[string]uint32{targetLabel(device): 1}, counts)
	}
	var rows strings.Builder
	for i := range 20000 {
		fmt.Fprint(&rows, row(fmt.Sprintf("dev%d", i)))
	}
	counts, err = parseARPCounts([]byte(rows.String() + row("dev0")))
	require.NoError(t, err)
	require.Len(t, counts, 20000)
	require.Equal(t, uint32(2), counts["dev0"])
	c, err := newARPCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	read := c.Reads()[0]
	for _, bad := range []string{
		"malformed", "a b c d e f g", strings.Repeat("a ", 10), strings.Repeat("x", 70000),
		"ip type 0x100 00:11:22:33:44:55 * eth0\n", "ip type nope 00:11:22:33:44:55 * eth0\n",
		"ip type 0x2 invalid * eth0\n", row(strings.Repeat("x", 4097)),
		row(strings.Repeat(string([]byte{0xff}), 1024)), rows.String() + row("overflow"),
	} {
		ch := make(chan prometheus.Metric, 21000)
		require.Error(t, c.Update(agentless.Target{}, agentless.Input{read.ID: {Output: []byte(row("good") + bad)}}, ch), "input %.80s", bad)
		require.Empty(t, ch, "no partial snapshot on parse/cap failure")
	}
}

func TestARPScraperIsolation(t *testing.T) {
	for _, missing := range []bool{false, true} {
		c, err := newARPCollector(DefaultConfigs(), nil)
		require.NoError(t, err)
		read := c.Reads()[0]
		in := agentless.Input{read.ID: {Read: read, Output: []byte("malformed")}}
		if missing {
			in[read.ID] = agentless.Result{Read: read, NotExist: true, ExitStatus: 1}
		}
		load := &loadavgCollector{}
		read = load.Reads()[0]
		in[read.ID] = agentless.Result{Read: read, Output: []byte("1 2 3 1/1 1\n")}
		scraper, err := agentless.NewScraper(&agentlesstest.FakeRunner{Results: in}, []agentless.Collector{c, load}, slog.New(slog.NewTextHandler(io.Discard, nil)))
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result, err := scraper.Scrape(ctx, agentless.Target{})
		require.NoError(t, err)
		registry := prometheus.NewRegistry()
		registry.MustRegister(result)
		families, err := registry.Gather()
		require.NoError(t, err)
		success := map[string]float64{}
		foundLoad := false
		for _, family := range families {
			require.NotEqual(t, "node_arp_entries", family.GetName())
			if family.GetName() == "node_load1" {
				foundLoad = true
				require.Equal(t, 1.0, family.Metric[0].GetGauge().GetValue())
			}
			if family.GetName() == "node_scrape_collector_success" {
				for _, metric := range family.Metric {
					success[metric.Label[0].GetValue()] = metric.GetGauge().GetValue()
				}
			}
		}
		require.True(t, foundLoad)
		require.Equal(t, 1.0, success["loadavg"])
		want := 0.0
		if missing {
			want = 1
		}
		require.Equal(t, want, success["arp"])
	}
}
