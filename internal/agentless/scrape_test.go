package agentless_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
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

// expandingCollector keeps the fixed Collector contract and opts into phase two.
type expandingCollector struct {
	name   string
	reads  []agentless.Read
	expand func(agentless.Target, agentless.Input) ([]agentless.Read, error)
	update func(agentless.Target, agentless.Input, chan<- prometheus.Metric) error
}

func (c expandingCollector) Name() string            { return c.name }
func (c expandingCollector) Reads() []agentless.Read { return c.reads }
func (c expandingCollector) Expand(target agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	return c.expand(target, in)
}
func (c expandingCollector) Update(target agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	return c.update(target, in, ch)
}

type recordingRunner struct {
	runner  agentless.Runner
	batches [][]agentless.Read
	fail    func(int, []agentless.Result) ([]agentless.Result, error)
}

func (r *recordingRunner) Run(ctx context.Context, target agentless.Target, reads []agentless.Read) ([]agentless.Result, error) {
	r.batches = append(r.batches, append([]agentless.Read(nil), reads...))
	results, err := r.runner.Run(ctx, target, reads)
	if err == nil && r.fail != nil {
		return r.fail(len(r.batches), results)
	}
	return results, err
}

func assertCollectorSuccess(t *testing.T, c prometheus.Collector, want map[string]float64) {
	t.Helper()
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(c))
	families, err := reg.Gather()
	require.NoError(t, err)
	got := make(map[string]float64)
	for _, family := range families {
		if family.GetName() == "node_scrape_collector_success" {
			for _, metric := range family.Metric {
				got[metric.Label[0].GetValue()] = metric.GetGauge().GetValue()
			}
		}
	}
	require.Equal(t, want, got)
}

func generatedReads(prefix string, n int) []agentless.Read {
	reads := make([]agentless.Read, n)
	for i := range reads {
		reads[i] = agentless.FileRead(fmt.Sprintf("/sys/%s/%d", prefix, i))
	}
	return reads
}

func TestScrapeExpanderTwoPhasesFromFixture(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sys/devices/b"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sys/devices/a"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sys/devices/.hidden"), 0o700))
	for _, name := range []string{"a", "b"} {
		require.NoError(t, os.WriteFile(filepath.Join(root, "sys/devices", name, "value"), []byte("42\n"), 0o600))
	}
	listing := agentless.CommandRead("ls", "-1", "/sys/devices")
	target := agentless.Target{Address: "fixture", Auth: "fixture-auth"}
	expansions, updates := 0, 0
	makeCollector := func(name string) expandingCollector {
		return expandingCollector{name: name, reads: []agentless.Read{listing},
			expand: func(got agentless.Target, in agentless.Input) ([]agentless.Read, error) {
				expansions++
				require.Equal(t, target, got)
				require.Len(t, in, 1, "every Expand sees only phase one")
				output, err := in.Output(listing)
				require.NoError(t, err)
				require.Equal(t, "a\nb\n", string(output))
				reads := []agentless.Read{listing} // Already present; never rerun it.
				for _, entry := range strings.Fields(string(output)) {
					reads = append(reads, agentless.FileRead("/sys/devices/"+entry+"/value"))
				}
				return append(reads, reads[1]), nil // Also deduplicate within a collector.
			},
			update: func(got agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
				updates++
				assert.Equal(t, target, got)
				assert.Len(t, in, 3)
				for _, entry := range []string{"a", "b"} {
					output, err := in.Output(agentless.FileRead("/sys/devices/" + entry + "/value"))
					assert.NoError(t, err)
					assert.Equal(t, "42\n", string(output))
				}
				ch <- prometheus.MustNewConstMetric(lineDesc, prometheus.GaugeValue, 2, name)
				return nil
			},
		}
	}
	fixture, err := agentlesstest.FromFS(root, nil, []agentless.Read{listing})
	require.NoError(t, err)
	runner := &recordingRunner{runner: fixture}
	s, err := agentless.NewScraper(runner, []agentless.Collector{makeCollector("a"), makeCollector("b")}, util.TestLogger(t))
	require.NoError(t, err)
	result, err := s.Scrape(t.Context(), target)
	require.NoError(t, err)
	require.Equal(t, [][]agentless.Read{{listing}, {agentless.FileRead("/sys/devices/a/value"), agentless.FileRead("/sys/devices/b/value")}}, runner.batches)
	require.Equal(t, 2, expansions, "exactly one Expand per collector, no recursive listing")
	assertCollectorSuccess(t, result, map[string]float64{"a": 1, "b": 1})
	require.Equal(t, 2, updates)
}

func TestScrapeExpansionFailuresAreIsolated(t *testing.T) {
	for _, tc := range []struct {
		name   string
		expand func(agentless.Target, agentless.Input) ([]agentless.Read, error)
	}{
		{"over cap", func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
			return generatedReads("bad", 1025), nil
		}},
		{"duplicate over cap", func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
			reads := make([]agentless.Read, 1025)
			for i := range reads {
				reads[i] = procStat
			}
			return reads, nil
		}},
		{"invalid path", func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
			return []agentless.Read{agentless.FileRead("/sys/bad/ok"), agentless.FileRead("/sys/bad/../escape")}, nil
		}},
		{"invalid command", func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
			return []agentless.Read{agentless.CommandRead("cat", "$(id)")}, nil
		}},
		{"error", func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
			return generatedReads("bad", 1), errors.New("listing failed")
		}},
		{"panic", func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
			panic("hostile listing")
		}},
		{"conflict fixed", func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
			return []agentless.Read{{ID: procStat.ID, Path: "/sys/bad/value"}}, nil
		}},
		{"conflict within expansion", func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
			return []agentless.Read{{ID: "conflict", Path: "/sys/bad/a"}, {ID: "conflict", Path: "/sys/bad/b"}}, nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			goodRead := agentless.FileRead("/sys/good/value")
			runner := &recordingRunner{runner: &agentlesstest.FakeRunner{Results: map[string]agentless.Result{
				procStat.ID: {Output: []byte("cpu 1\n")}, goodRead.ID: {Output: []byte("ok\n")},
			}}}
			bad := expandingCollector{name: "bad", expand: tc.expand,
				update: func(agentless.Target, agentless.Input, chan<- prometheus.Metric) error {
					t.Error("rejected collector must not Update")
					return nil
				}}
			good := expandingCollector{name: "expanded", expand: func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
				return []agentless.Read{goodRead}, nil
			}, update: func(_ agentless.Target, in agentless.Input, _ chan<- prometheus.Metric) error {
				_, err := in.Output(goodRead)
				return err
			}}
			s, err := agentless.NewScraper(runner, []agentless.Collector{bad, good, lineCounter{"fixed"}}, util.TestLogger(t))
			require.NoError(t, err)
			result, err := s.Scrape(t.Context(), agentless.Target{})
			require.NoError(t, err)
			require.Equal(t, [][]agentless.Read{{procStat}, {goodRead}}, runner.batches, "no rejected read may reach Runner")
			assertCollectorSuccess(t, result, map[string]float64{"bad": 0, "expanded": 1, "fixed": 1})
		})
	}
}

func TestScrapeExpansionScrapeCap(t *testing.T) {
	runner := &recordingRunner{runner: &agentlesstest.FakeRunner{}}
	var collectors []agentless.Collector
	want := map[string]float64{}
	for i := 0; i < 6; i++ {
		name := fmt.Sprintf("expanded%d", i)
		reads := generatedReads(name, 1024)
		// Four batches fill the scrape cap exactly. One additional read from
		// the fifth fails; the sixth shares admitted reads without more capacity.
		switch i {
		case 4:
			reads = generatedReads(name, 1)
		case 5:
			reads = generatedReads("expanded0", 1024)
		}
		collectors = append(collectors, expandingCollector{name: name,
			expand: func(agentless.Target, agentless.Input) ([]agentless.Read, error) { return reads, nil },
			update: func(_ agentless.Target, in agentless.Input, _ chan<- prometheus.Metric) error {
				assert.NotEqual(t, 4, i, "over-scrape-cap collector must not Update")
				assert.Len(t, in, 4096)
				return nil
			}})
		want[name] = 1
		if i == 4 {
			want[name] = 0
		}
	}
	s, err := agentless.NewScraper(runner, collectors, util.TestLogger(t))
	require.NoError(t, err)
	result, err := s.Scrape(t.Context(), agentless.Target{})
	require.NoError(t, err)
	require.Len(t, runner.batches, 2)
	require.Len(t, runner.batches[1], 4096)
	assertCollectorSuccess(t, result, want)
}

func TestScrapeExpansionConflictingCollectors(t *testing.T) {
	read := agentless.FileRead("/sys/good/value")
	runner := &recordingRunner{runner: &agentlesstest.FakeRunner{Results: map[string]agentless.Result{read.ID: {Output: []byte("ok\n")}}}}
	good := expandingCollector{name: "good",
		expand: func(agentless.Target, agentless.Input) ([]agentless.Read, error) { return []agentless.Read{read}, nil },
		update: func(_ agentless.Target, in agentless.Input, _ chan<- prometheus.Metric) error {
			_, err := in.Output(read)
			return err
		}}
	bad := expandingCollector{name: "bad",
		expand: func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
			return []agentless.Read{agentless.FileRead("/sys/bad/value"), {ID: read.ID, Path: "/sys/bad/conflict"}}, nil
		},
		update: func(agentless.Target, agentless.Input, chan<- prometheus.Metric) error {
			t.Error("conflicting collector must not Update")
			return nil
		}}
	s, err := agentless.NewScraper(runner, []agentless.Collector{good, bad}, util.TestLogger(t))
	require.NoError(t, err)
	result, err := s.Scrape(t.Context(), agentless.Target{})
	require.NoError(t, err)
	require.Len(t, runner.batches, 2)
	require.Equal(t, []agentless.Read{read}, runner.batches[1], "reject all conflicting collector reads")
	assertCollectorSuccess(t, result, map[string]float64{"good": 1, "bad": 0})
}

func TestScrapeExpansionEmptyOrFixedNeedsNoSecondBatch(t *testing.T) {
	for _, reads := range [][]agentless.Read{nil, {procStat}} {
		runner := &agentlesstest.FakeRunner{Results: map[string]agentless.Result{procStat.ID: {Output: []byte("cpu 1\n")}}}
		c := expandingCollector{name: "expanded", reads: []agentless.Read{procStat},
			expand: func(agentless.Target, agentless.Input) ([]agentless.Read, error) { return reads, nil },
			update: func(_ agentless.Target, in agentless.Input, _ chan<- prometheus.Metric) error {
				_, err := in.Output(procStat)
				return err
			}}
		s, err := agentless.NewScraper(runner, []agentless.Collector{c}, util.TestLogger(t))
		require.NoError(t, err)
		result, err := s.Scrape(t.Context(), agentless.Target{})
		require.NoError(t, err)
		require.Equal(t, 1, runner.Calls())
		assertCollectorSuccess(t, result, map[string]float64{"expanded": 1})
	}
}

type deepCollector struct {
	expandingCollector
	deep func(agentless.Target, agentless.Input) ([]agentless.Read, error)
}

func (c deepCollector) ExpandDeep(target agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	return c.deep(target, in)
}

func TestScrapeDeepThreePhasesFromFixture(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a", "b"} {
		dir := filepath.Join(root, "sys/devices", name)
		require.NoError(t, os.MkdirAll(dir, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "value"), []byte("42\n"), 0o600))
	}
	listing := agentless.CommandRead("ls", "-1", "/sys/devices")
	target := agentless.Target{Address: "fixture", Auth: "fixture-auth"}
	expansions, deepExpansions, updates := 0, 0, 0
	makeCollector := func(name string) deepCollector {
		return deepCollector{expandingCollector: expandingCollector{name: name, reads: []agentless.Read{listing},
			expand: func(got agentless.Target, in agentless.Input) ([]agentless.Read, error) {
				expansions++
				require.Equal(t, target, got)
				require.Len(t, in, 1)
				output, err := in.Output(listing)
				require.NoError(t, err)
				var reads []agentless.Read
				for _, entry := range strings.Fields(string(output)) {
					reads = append(reads, agentless.CommandRead("ls", "-1", "/sys/devices/"+entry))
				}
				return reads, nil
			},
			update: func(got agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
				updates++
				assert.Equal(t, target, got)
				assert.Len(t, in, 5)
				for _, entry := range []string{"a", "b"} {
					output, err := in.Output(agentless.FileRead("/sys/devices/" + entry + "/value"))
					assert.NoError(t, err)
					assert.Equal(t, "42\n", string(output))
				}
				ch <- prometheus.MustNewConstMetric(lineDesc, prometheus.GaugeValue, 2, name)
				return nil
			}},
			deep: func(got agentless.Target, in agentless.Input) ([]agentless.Read, error) {
				deepExpansions++
				require.Equal(t, target, got)
				require.Len(t, in, 3, "ExpandDeep sees phases one and two, never phase three")
				output, err := in.Output(listing)
				require.NoError(t, err)
				var reads []agentless.Read
				for _, entry := range strings.Fields(string(output)) {
					second := agentless.CommandRead("ls", "-1", "/sys/devices/"+entry)
					files, err := in.Output(second)
					require.NoError(t, err)
					for _, file := range strings.Fields(string(files)) {
						reads = append(reads, agentless.FileRead("/sys/devices/"+entry+"/"+file))
					}
				}
				return append(reads, reads[0]), nil
			},
		}
	}
	fixture, err := agentlesstest.FromFS(root, nil, []agentless.Read{listing})
	require.NoError(t, err)
	runner := &recordingRunner{runner: fixture}
	s, err := agentless.NewScraper(runner, []agentless.Collector{makeCollector("a"), makeCollector("b")}, util.TestLogger(t))
	require.NoError(t, err)
	result, err := s.Scrape(t.Context(), target)
	require.NoError(t, err)
	require.Equal(t, [][]agentless.Read{{listing},
		{agentless.CommandRead("ls", "-1", "/sys/devices/a"), agentless.CommandRead("ls", "-1", "/sys/devices/b")},
		{agentless.FileRead("/sys/devices/a/value"), agentless.FileRead("/sys/devices/b/value")}}, runner.batches)
	require.Equal(t, 2, expansions)
	require.Equal(t, 2, deepExpansions, "called once per collector, no fourth phase")
	assertCollectorSuccess(t, result, map[string]float64{"a": 1, "b": 1})
	require.Equal(t, 2, updates)
}

func TestScrapeDeepListingCap(t *testing.T) {
	for _, n := range []int{64, 65} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			listing := agentless.CommandRead("ls", "-1", "/sys/devices")
			var names strings.Builder
			for i := 0; i < n; i++ {
				fmt.Fprintf(&names, "%d\n", i)
			}
			runner := &recordingRunner{runner: &agentlesstest.FakeRunner{Results: map[string]agentless.Result{
				listing.ID: {Output: []byte(names.String())}, procStat.ID: {Output: []byte("cpu 1\n")},
			}}}
			deepCalls, updates := 0, 0
			c := deepCollector{expandingCollector: expandingCollector{name: "deep", reads: []agentless.Read{listing},
				expand: func(_ agentless.Target, in agentless.Input) ([]agentless.Read, error) {
					output, err := in.Output(listing)
					require.NoError(t, err)
					var reads []agentless.Read
					for _, name := range strings.Fields(string(output)) {
						reads = append(reads, agentless.CommandRead("ls", "-1", "/sys/devices/"+name))
					}
					return reads, nil
				}, update: func(_ agentless.Target, _ agentless.Input, ch chan<- prometheus.Metric) error {
					updates++
					ch <- prometheus.MustNewConstMetric(lineDesc, prometheus.GaugeValue, 1, "deep")
					return nil
				}}, deep: func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
				deepCalls++
				return nil, nil
			}}
			s, err := agentless.NewScraper(runner, []agentless.Collector{c, lineCounter{"fixed"}}, util.TestLogger(t))
			require.NoError(t, err)
			result, err := s.Scrape(t.Context(), agentless.Target{})
			require.NoError(t, err)
			want := float64(1)
			if n == 65 {
				want = 0
			}
			assertCollectorSuccess(t, result, map[string]float64{"deep": want, "fixed": 1})
			require.Equal(t, int(want), deepCalls)
			require.Equal(t, int(want), updates)
			require.Equal(t, 1+int(want), len(runner.batches), "no third batch for empty deep reads; no partial phase two on rejection")
			require.Equal(t, 1+int(want), testutil.CollectAndCount(result, "node_test_lines"))
			if n == 64 {
				require.Len(t, runner.batches[1], 64)
			}
		})
	}
}

func capDeepCollector(name string, second, third []agentless.Read, updates *int) deepCollector {
	return deepCollector{expandingCollector: expandingCollector{name: name,
		expand: func(agentless.Target, agentless.Input) ([]agentless.Read, error) { return second, nil },
		update: func(_ agentless.Target, _ agentless.Input, ch chan<- prometheus.Metric) error {
			*updates++
			ch <- prometheus.MustNewConstMetric(lineDesc, prometheus.GaugeValue, 1, name)
			return nil
		}}, deep: func(agentless.Target, agentless.Input) ([]agentless.Read, error) { return third, nil }}
}

func TestScrapeDeepCombinedCollectorCap(t *testing.T) {
	for _, n := range []int{512, 513} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			runner := &recordingRunner{runner: &agentlesstest.FakeRunner{}}
			updates, goodUpdates := 0, 0
			c := capDeepCollector("deep", generatedReads("second", 512), generatedReads("third", n), &updates)
			good := capDeepCollector("good", nil, generatedReads("good", 1), &goodUpdates)
			s, err := agentless.NewScraper(runner, []agentless.Collector{c, good}, util.TestLogger(t))
			require.NoError(t, err)
			result, err := s.Scrape(t.Context(), agentless.Target{})
			require.NoError(t, err)
			want := float64(1)
			if n == 513 {
				want = 0
			}
			assertCollectorSuccess(t, result, map[string]float64{"deep": want, "good": 1})
			require.Equal(t, int(want), updates, "combined overflow skips whole collector Update")
			require.Equal(t, 1, goodUpdates)
			require.Len(t, runner.batches, 3)
			require.Len(t, runner.batches[1], 512)
			require.Len(t, runner.batches[2], int(want)*n+1, "no rejected phase-three reads")
			require.Equal(t, int(want)+1, testutil.CollectAndCount(result, "node_test_lines"))
		})
	}
}

func TestScrapeDeepCombinedScrapeCap(t *testing.T) {
	for _, overflow := range []bool{false, true} {
		t.Run(fmt.Sprint(overflow), func(t *testing.T) {
			runner := &recordingRunner{runner: &agentlesstest.FakeRunner{}}
			var collectors []agentless.Collector
			want := map[string]float64{}
			updates := make([]int, 6)
			for i := 0; i < 4; i++ {
				name := fmt.Sprintf("deep%d", i)
				collectors = append(collectors, capDeepCollector(name, generatedReads(name+"second", 512), generatedReads(name+"third", 512), &updates[i]))
				want[name] = 1
			}
			// A collector can share already admitted reads even at the cap.
			extra := []agentless.Read{generatedReads("deep0third", 1)[0]}
			want["extra"] = 1
			if overflow {
				extra = append(extra, generatedReads("overflow", 1)...)
				want["extra"] = 0
			}
			collectors = append(collectors, capDeepCollector("extra", nil, extra, &updates[4]),
				capDeepCollector("shared", nil, generatedReads("deep0third", 512), &updates[5]))
			want["shared"] = 1
			s, err := agentless.NewScraper(runner, collectors, util.TestLogger(t))
			require.NoError(t, err)
			result, err := s.Scrape(t.Context(), agentless.Target{})
			require.NoError(t, err)
			assertCollectorSuccess(t, result, want)
			require.Len(t, runner.batches, 3)
			require.Len(t, runner.batches[1], 2048)
			require.Len(t, runner.batches[2], 2048, "combined phase-two and phase-three scrape cap is 4096")
			require.Equal(t, int(want["extra"]), updates[4])
			require.Equal(t, 1, updates[5])
			require.Equal(t, 5+int(want["extra"]), testutil.CollectAndCount(result, "node_test_lines"))
		})
	}
}

func TestScrapeDeepFailuresAreIsolated(t *testing.T) {
	second := agentless.FileRead("/sys/second")
	for _, tc := range []struct {
		name  string
		reads []agentless.Read
		deep  func(agentless.Target, agentless.Input) ([]agentless.Read, error)
	}{
		{"invalid listing command", []agentless.Read{agentless.CommandRead("ls", "-R", "/sys")}, nil},
		{"relative listing", []agentless.Read{agentless.CommandRead("ls", "-1", "sys")}, nil},
		{"unsafe listing", []agentless.Read{agentless.CommandRead("ls", "-1", "/sys/../escape")}, nil},
		{"error", nil, func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
			return nil, errors.New("deep failed")
		}},
		{"panic", nil, func(agentless.Target, agentless.Input) ([]agentless.Read, error) { panic("deep panic") }},
		{"invalid file", nil, func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
			return []agentless.Read{agentless.FileRead("/sys/bad/ok"), agentless.FileRead("/sys/../escape")}, nil
		}},
		{"fourth phase listing", nil, func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
			return []agentless.Read{agentless.CommandRead("ls", "-1", "/sys")}, nil
		}},
		{"conflict second", nil, func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
			return []agentless.Read{agentless.FileRead("/sys/bad/ok"), {ID: second.ID, Path: "/sys/conflict"}}, nil
		}},
		{"conflict fixed", nil, func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
			return []agentless.Read{{ID: procStat.ID, Path: "/sys/conflict"}}, nil
		}},
		{"conflict local", nil, func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
			return []agentless.Read{{ID: "duplicate", Path: "/sys/a"}, {ID: "duplicate", Path: "/sys/b"}}, nil
		}},
		{"duplicate combined overflow", nil, func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
			reads := make([]agentless.Read, 1024)
			for i := range reads {
				reads[i] = second
			}
			return reads, nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &recordingRunner{runner: &agentlesstest.FakeRunner{Results: map[string]agentless.Result{procStat.ID: {Output: []byte("cpu 1\n")}}}}
			if tc.reads == nil {
				tc.reads = []agentless.Read{second}
			}
			if tc.deep == nil {
				tc.deep = func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
					t.Error("invalid phase two must skip ExpandDeep")
					return nil, nil
				}
			}
			updates, goodUpdates := 0, 0
			bad := capDeepCollector("bad", tc.reads, nil, &updates)
			bad.deep = tc.deep
			goodRead := agentless.FileRead("/sys/good/value")
			good := capDeepCollector("good", nil, []agentless.Read{goodRead}, &goodUpdates)
			s, err := agentless.NewScraper(runner, []agentless.Collector{bad, good, lineCounter{"fixed"}}, util.TestLogger(t))
			require.NoError(t, err)
			result, err := s.Scrape(t.Context(), agentless.Target{})
			require.NoError(t, err)
			assertCollectorSuccess(t, result, map[string]float64{"bad": 0, "good": 1, "fixed": 1})
			require.Zero(t, updates)
			require.Equal(t, 1, goodUpdates)
			require.Equal(t, []agentless.Read{goodRead}, runner.batches[len(runner.batches)-1], "atomic deep rejection")
			require.Equal(t, 2, testutil.CollectAndCount(result, "node_test_lines"))
		})
	}
}

func TestScrapeDeepBatchFailureKeepsEarlierResults(t *testing.T) {
	for _, phase := range []int{2, 3} {
		for _, mode := range []string{"error", "short", "wrong ID", "failed read"} {
			t.Run(fmt.Sprintf("%d/%s", phase, mode), func(t *testing.T) {
				second, third := agentless.FileRead("/sys/second"), agentless.FileRead("/sys/third")
				runner := &recordingRunner{runner: &agentlesstest.FakeRunner{Results: map[string]agentless.Result{
					procStat.ID: {Output: []byte("cpu 1\n")}, second.ID: {}, third.ID: {},
				}}, fail: func(call int, results []agentless.Result) ([]agentless.Result, error) {
					if call != phase {
						return results, nil
					}
					switch mode {
					case "error":
						return nil, errors.New("deep batch transport failed")
					case "short":
						return nil, nil
					case "wrong ID":
						results[0].Read = procStat
					case "failed read":
						results[0].ExitStatus = 1
					}
					return results, nil
				}}
				deepCalls := 0
				c := deepCollector{expandingCollector: expandingCollector{name: "deep",
					expand: func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
						return []agentless.Read{second}, nil
					},
					update: func(_ agentless.Target, in agentless.Input, _ chan<- prometheus.Metric) error {
						assert.Equal(t, "failed read", mode)
						_, err := in.Output(third)
						return err
					}}, deep: func(_ agentless.Target, in agentless.Input) ([]agentless.Read, error) {
					deepCalls++
					if _, err := in.Output(second); err != nil {
						return nil, err
					}
					return []agentless.Read{third}, nil
				}}
				prior := expandingCollector{name: "prior", expand: func(agentless.Target, agentless.Input) ([]agentless.Read, error) {
					if phase == 3 {
						return []agentless.Read{second}, nil
					}
					return nil, nil
				}, update: func(agentless.Target, agentless.Input, chan<- prometheus.Metric) error { return nil }}
				s, err := agentless.NewScraper(runner, []agentless.Collector{c, prior, lineCounter{"fixed"}}, util.TestLogger(t))
				require.NoError(t, err)
				result, err := s.Scrape(t.Context(), agentless.Target{})
				require.NoError(t, err)
				assertCollectorSuccess(t, result, map[string]float64{"deep": 0, "prior": 1, "fixed": 1})
				require.Len(t, runner.batches, phase)
				wantDeep := 1
				if phase == 2 && mode != "failed read" {
					wantDeep = 0
				}
				require.Equal(t, wantDeep, deepCalls)
			})
		}
	}
}

func TestScrapeDeepEmptyNeedsNoThirdBatch(t *testing.T) {
	for _, second := range [][]agentless.Read{nil, {procStat}, generatedReads("second", 1)} {
		for _, third := range [][]agentless.Read{nil, {procStat}} {
			runner := &recordingRunner{runner: &agentlesstest.FakeRunner{}}
			updates, deepCalls := 0, 0
			c := capDeepCollector("deep", second, third, &updates)
			c.reads = []agentless.Read{procStat}
			c.deep = func(agentless.Target, agentless.Input) ([]agentless.Read, error) { deepCalls++; return third, nil }
			s, err := agentless.NewScraper(runner, []agentless.Collector{c}, util.TestLogger(t))
			require.NoError(t, err)
			result, err := s.Scrape(t.Context(), agentless.Target{})
			require.NoError(t, err)
			assertCollectorSuccess(t, result, map[string]float64{"deep": 1})
			require.Equal(t, 1, deepCalls)
			calls := 1
			if len(second) != 0 && second[0].ID != procStat.ID {
				calls = 2
			}
			require.Len(t, runner.batches, calls)
		}
	}
}

func TestScrapeExpansionBatchFailureKeepsFixedResults(t *testing.T) {
	for _, mode := range []string{"error", "short", "wrong ID", "failed read"} {
		t.Run(mode, func(t *testing.T) {
			read := agentless.FileRead("/sys/value")
			runner := &recordingRunner{runner: &agentlesstest.FakeRunner{Results: map[string]agentless.Result{
				procStat.ID: {Output: []byte("cpu 1\n")},
			}}, fail: func(call int, results []agentless.Result) ([]agentless.Result, error) {
				if call == 1 {
					return results, nil
				}
				switch mode {
				case "error":
					return nil, errors.New("second batch transport failed")
				case "short":
					return nil, nil
				case "wrong ID":
					results[0].Read = procStat
				}
				return results, nil
			}}
			c := expandingCollector{name: "expanded",
				expand: func(agentless.Target, agentless.Input) ([]agentless.Read, error) { return []agentless.Read{read}, nil },
				update: func(_ agentless.Target, in agentless.Input, _ chan<- prometheus.Metric) error {
					assert.Equal(t, "failed read", mode, "untrustworthy second batch must skip Update")
					_, err := in.Output(read)
					return err
				}}
			s, err := agentless.NewScraper(runner, []agentless.Collector{c, lineCounter{"fixed"}}, util.TestLogger(t))
			require.NoError(t, err)
			result, err := s.Scrape(t.Context(), agentless.Target{})
			require.NoError(t, err)
			assertCollectorSuccess(t, result, map[string]float64{"expanded": 0, "fixed": 1})
		})
	}
}
