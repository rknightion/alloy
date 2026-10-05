package agentless_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/grafana/alloy/internal/util"
)

var procStat = agentless.FileRead("/proc/stat")

// lineCounter emits the number of lines in /proc/stat, or fails when the read
// failed.
type lineCounter struct{ name string }

var lineDesc = prometheus.NewDesc("node_test_lines", "Lines read.", []string{"collector"}, nil)

func (c lineCounter) Name() string            { return c.name }
func (c lineCounter) Reads() []agentless.Read { return []agentless.Read{procStat} }
func (c lineCounter) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	b, err := in.Output(procStat)
	if err != nil {
		return err
	}
	ch <- prometheus.MustNewConstMetric(lineDesc, prometheus.GaugeValue, float64(strings.Count(string(b), "\n")), c.name)
	return nil
}

func TestScrapeSharesReadsAndReportsSuccess(t *testing.T) {
	runner := &agentlesstest.FakeRunner{Results: map[string]agentless.Result{
		procStat.ID: {Output: []byte("cpu 1 2 3\nctxt 4\n")},
	}}
	s, err := agentless.NewScraper(runner, []agentless.Collector{lineCounter{"a"}, lineCounter{"b"}}, util.TestLogger(t))
	require.NoError(t, err)
	require.Len(t, s.Reads(), 1, "two collectors reading /proc/stat share one read")

	c, err := s.Scrape(t.Context(), agentless.Target{Address: "host"})
	require.NoError(t, err)
	require.Equal(t, 1, runner.Calls())

	err = testutil.CollectAndCompare(c, strings.NewReader(`
# HELP node_scrape_collector_success node_exporter: Whether a collector succeeded.
# TYPE node_scrape_collector_success gauge
node_scrape_collector_success{collector="a"} 1
node_scrape_collector_success{collector="b"} 1
# HELP node_test_lines Lines read.
# TYPE node_test_lines gauge
node_test_lines{collector="a"} 2
node_test_lines{collector="b"} 2
`), "node_scrape_collector_success", "node_test_lines")
	require.NoError(t, err)
}

var procMeminfo = agentless.FileRead("/proc/meminfo")

// meminfoLines is a lineCounter over /proc/meminfo.
type meminfoLines struct{}

func (meminfoLines) Name() string            { return "meminfo" }
func (meminfoLines) Reads() []agentless.Read { return []agentless.Read{procMeminfo} }
func (meminfoLines) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	b, err := in.Output(procMeminfo)
	if err != nil {
		return err
	}
	ch <- prometheus.MustNewConstMetric(lineDesc, prometheus.GaugeValue, float64(strings.Count(string(b), "\n")), "meminfo")
	return nil
}

// panicker panics on every scrape, as a parser might on hostile output.
type panicker struct{}

func (panicker) Name() string            { return "panicker" }
func (panicker) Reads() []agentless.Read { return []agentless.Read{procStat} }
func (panicker) Update(agentless.Target, agentless.Input, chan<- prometheus.Metric) error {
	panic("index out of range")
}

func TestScrapeFailedReadAndPanicFailOnlyTheirCollectors(t *testing.T) {
	runner := &agentlesstest.FakeRunner{Results: map[string]agentless.Result{
		procStat.ID:    {ExitStatus: 1, NotExist: true},
		procMeminfo.ID: {Output: []byte("MemTotal: 1 kB\n")},
	}}
	s, err := agentless.NewScraper(runner, []agentless.Collector{lineCounter{"a"}, panicker{}, meminfoLines{}}, util.TestLogger(t))
	require.NoError(t, err)

	c, err := s.Scrape(t.Context(), agentless.Target{Address: "host"})
	require.NoError(t, err)
	err = testutil.CollectAndCompare(c, strings.NewReader(`
# HELP node_scrape_collector_success node_exporter: Whether a collector succeeded.
# TYPE node_scrape_collector_success gauge
node_scrape_collector_success{collector="a"} 0
node_scrape_collector_success{collector="meminfo"} 1
node_scrape_collector_success{collector="panicker"} 0
# HELP node_test_lines Lines read.
# TYPE node_test_lines gauge
node_test_lines{collector="meminfo"} 1
`), "node_scrape_collector_success", "node_test_lines")
	require.NoError(t, err)
	require.Equal(t, 3, testutil.CollectAndCount(c, "node_scrape_collector_duration_seconds"))
}

func TestScrapeTransportErrorFailsScrape(t *testing.T) {
	boom := errors.New("connection refused")
	s, err := agentless.NewScraper(&agentlesstest.FakeRunner{Err: boom}, []agentless.Collector{lineCounter{"a"}}, util.TestLogger(t))
	require.NoError(t, err)

	_, err = s.Scrape(context.Background(), agentless.Target{Address: "host"})
	require.ErrorIs(t, err, boom)
}

type badReads struct{ reads []agentless.Read }

func (c badReads) Name() string            { return "bad" }
func (c badReads) Reads() []agentless.Read { return c.reads }
func (c badReads) Update(agentless.Target, agentless.Input, chan<- prometheus.Metric) error {
	return nil
}

func TestNewScraperRejectsUnsafeReads(t *testing.T) {
	for _, r := range []agentless.Read{
		agentless.FileRead("/proc/stat; rm -rf /"),
		agentless.FileRead("relative/path"),
		agentless.FileRead("/proc/../etc/shadow"),
		agentless.CommandRead("df", "$(id)"),
		agentless.CommandRead("cat", "a b"),
		{ID: "both", Path: "/proc/stat", Argv: []string{"df"}},
		{ID: "neither"},
	} {
		_, err := agentless.NewScraper(&agentlesstest.FakeRunner{}, []agentless.Collector{badReads{[]agentless.Read{r}}}, util.TestLogger(t))
		require.Error(t, err, "read %+v", r)
	}
}

func TestNewScraperRejectsConflictingReadIDs(t *testing.T) {
	conflict := agentless.Read{ID: procStat.ID, Path: "/proc/meminfo"}
	_, err := agentless.NewScraper(&agentlesstest.FakeRunner{}, []agentless.Collector{
		lineCounter{"a"}, badReads{[]agentless.Read{conflict}},
	}, util.TestLogger(t))
	require.Error(t, err)
}

func TestValidateRejectsAssignmentAsCommand(t *testing.T) {
	require.Error(t, agentless.CommandRead("PATH=/tmp", "df").Validate())
	require.Error(t, agentless.CommandRead("cat", "/proc/../etc/shadow").Validate())
	require.NoError(t, agentless.CommandRead("df", "-kPT").Validate())
}
