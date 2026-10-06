package agentless_test

import (
	"context"
	"errors"
	"fmt"
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

type outputCollector struct {
	name   string
	update func(chan<- prometheus.Metric) error
}

func (c outputCollector) Name() string            { return c.name }
func (c outputCollector) Reads() []agentless.Read { return nil }
func (c outputCollector) Update(_ agentless.Target, _ agentless.Input, ch chan<- prometheus.Metric) error {
	return c.update(ch)
}

func TestScrapeOutputLimits(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		series, families, labelBytes int
		wantSuccess                  float64
		escapedFamily                bool
	}{
		{"series at limit", 20000, 1, 1, 1, false},
		{"series overflow", 20001, 1, 1, 0, false},
		{"families at limit", 500, 500, 1, 1, false},
		{"families overflow", 501, 501, 1, 0, false},
		{"escaped families overflow", 501, 501, 1, 0, true},
		{"label at limit", 1, 1, 4096, 1, false},
		{"label overflow", 1, 1, 4097, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			finished := false
			bad := outputCollector{"bounded", func(ch chan<- prometheus.Metric) error {
				for i := 0; i < tc.series; i++ {
					format := "node_bounded_%d"
					if tc.escapedFamily {
						format = "node_bounded_\"%d"
					}
					desc := prometheus.NewDesc(fmt.Sprintf(format, i%tc.families), "Bounded.", []string{"id", "value"}, nil)
					ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, 1, fmt.Sprint(i), strings.Repeat("x", tc.labelBytes))
				}
				finished = true
				return nil
			}}
			good := outputCollector{"good", func(ch chan<- prometheus.Metric) error {
				ch <- prometheus.MustNewConstMetric(lineDesc, prometheus.GaugeValue, 1, "good")
				return nil
			}}
			s, err := agentless.NewScraper(&agentlesstest.FakeRunner{}, []agentless.Collector{bad, good}, util.TestLogger(t))
			require.NoError(t, err)
			c, err := s.Scrape(t.Context(), agentless.Target{})
			require.NoError(t, err)
			reg := prometheus.NewRegistry()
			require.NoError(t, reg.Register(c))
			families, err := reg.Gather()
			require.NoError(t, err)
			require.True(t, finished, "producer must finish even after overflow")
			series, successes := 0, 0
			for _, f := range families {
				if strings.HasPrefix(f.GetName(), "node_bounded_") {
					series += len(f.Metric)
				}
				if f.GetName() == "node_scrape_collector_success" {
					for _, m := range f.Metric {
						successes++
						if m.Label[0].GetValue() == "bounded" {
							require.Equal(t, tc.wantSuccess, m.GetGauge().GetValue())
						} else {
							require.Equal(t, float64(1), m.GetGauge().GetValue())
						}
					}
				}
			}
			require.Equal(t, 2, successes)
			if tc.wantSuccess == 0 {
				require.Zero(t, series, "overflow must discard the entire collector")
			} else {
				require.Equal(t, tc.series, series)
			}
			require.NoError(t, testutil.CollectAndCompare(c, strings.NewReader(`
# HELP node_test_lines Lines read.
# TYPE node_test_lines gauge
node_test_lines{collector="good"} 1
`), "node_test_lines"))
		})
	}
}

func TestScrapeConstLabelsAndFamilyIdentity(t *testing.T) {
	for _, labelBytes := range []int{4096, 4097} {
		t.Run(fmt.Sprint(labelBytes), func(t *testing.T) {
			c := outputCollector{"constant", func(ch chan<- prometheus.Metric) error {
				// These descriptors differ, but belong to a single family.
				for i := 0; i < 501; i++ {
					desc := prometheus.NewDesc("node_constant", "Constant.", nil, prometheus.Labels{"value": strings.Repeat("x", labelBytes), "id": fmt.Sprint(i)})
					ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, 1)
				}
				return nil
			}}
			s, err := agentless.NewScraper(&agentlesstest.FakeRunner{}, []agentless.Collector{c}, util.TestLogger(t))
			require.NoError(t, err)
			result, err := s.Scrape(t.Context(), agentless.Target{})
			require.NoError(t, err)
			wantSeries, wantSuccess := 501, 1
			if labelBytes == 4097 {
				wantSeries, wantSuccess = 0, 0
			}
			require.Equal(t, wantSeries, testutil.CollectAndCount(result, "node_constant"))
			require.NoError(t, testutil.CollectAndCompare(result, strings.NewReader(fmt.Sprintf(`
# HELP node_scrape_collector_success node_exporter: Whether a collector succeeded.
# TYPE node_scrape_collector_success gauge
node_scrape_collector_success{collector="constant"} %d
`, wantSuccess)), "node_scrape_collector_success"))
		})
	}
}

func TestScrapeFailedProducerPreservesPartialOutput(t *testing.T) {
	for _, panicAfterSend := range []bool{false, true} {
		t.Run(fmt.Sprint(panicAfterSend), func(t *testing.T) {
			c := outputCollector{"failed", func(ch chan<- prometheus.Metric) error {
				ch <- prometheus.MustNewConstMetric(lineDesc, prometheus.GaugeValue, 1, "failed")
				if panicAfterSend {
					panic("after send")
				}
				return errors.New("after send")
			}}
			s, err := agentless.NewScraper(&agentlesstest.FakeRunner{}, []agentless.Collector{c}, util.TestLogger(t))
			require.NoError(t, err)
			result, err := s.Scrape(t.Context(), agentless.Target{})
			require.NoError(t, err)
			require.NoError(t, testutil.CollectAndCompare(result, strings.NewReader(`
# HELP node_scrape_collector_success node_exporter: Whether a collector succeeded.
# TYPE node_scrape_collector_success gauge
node_scrape_collector_success{collector="failed"} 0
# HELP node_test_lines Lines read.
# TYPE node_test_lines gauge
node_test_lines{collector="failed"} 1
`), "node_scrape_collector_success", "node_test_lines"))
		})
	}
}

func TestScrapeEndedContextSkipsCollectors(t *testing.T) {
	for _, duringUpdate := range []bool{false, true} {
		t.Run(fmt.Sprint(duringUpdate), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			first := outputCollector{"first", func(ch chan<- prometheus.Metric) error {
				calls++
				cancel()
				ch <- prometheus.MustNewConstMetric(lineDesc, prometheus.GaugeValue, 1, "first")
				return nil
			}}
			later := outputCollector{"later", func(chan<- prometheus.Metric) error {
				t.Error("later collector must not run")
				return nil
			}}
			s, err := agentless.NewScraper(&agentlesstest.FakeRunner{}, []agentless.Collector{first, later}, util.TestLogger(t))
			require.NoError(t, err)
			c, err := s.Scrape(ctx, agentless.Target{})
			require.NoError(t, err)
			if !duringUpdate {
				cancel()
			}
			require.NoError(t, testutil.CollectAndCompare(c, strings.NewReader(`
# HELP node_scrape_collector_success node_exporter: Whether a collector succeeded.
# TYPE node_scrape_collector_success gauge
node_scrape_collector_success{collector="first"} 0
node_scrape_collector_success{collector="later"} 0
`), "node_scrape_collector_success", "node_test_lines"))
			if duringUpdate {
				require.Equal(t, 1, calls)
			} else {
				require.Zero(t, calls)
			}
		})
	}
}

func TestValidateRejectsAssignmentAsCommand(t *testing.T) {
	require.Error(t, agentless.CommandRead("PATH=/tmp", "df").Validate())
	require.Error(t, agentless.CommandRead("cat", "/proc/../etc/shadow").Validate())
	require.NoError(t, agentless.CommandRead("df", "-kPT").Validate())
}
