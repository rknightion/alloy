package collectors_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/grafana/alloy/internal/agentless/collectors"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/grafana/alloy/internal/util"
)

var diskFamilies = []string{
	"node_disk_reads_completed_total", "node_disk_reads_merged_total", "node_disk_read_bytes_total", "node_disk_read_time_seconds_total",
	"node_disk_writes_completed_total", "node_disk_writes_merged_total", "node_disk_written_bytes_total", "node_disk_write_time_seconds_total",
	"node_disk_io_now", "node_disk_io_time_seconds_total", "node_disk_io_time_weighted_seconds_total",
	"node_disk_discards_completed_total", "node_disk_discards_merged_total", "node_disk_discarded_sectors_total", "node_disk_discard_time_seconds_total",
	"node_disk_flush_requests_total", "node_disk_flush_requests_time_seconds_total",
}

func buildDisk(t *testing.T, cfg collectors.DiskstatsConfig) agentless.Collector {
	t.Helper()
	configs := collectors.DefaultConfigs()
	configs.Diskstats = cfg
	cs, err := collectors.Build([]string{"diskstats"}, configs, util.TestLogger(t))
	require.NoError(t, err)
	return cs[0]
}

func TestDiskstatsConformance(t *testing.T) {
	// The pinned oracle covers all /proc families, including discard and flush.
	// /sys and udev-derived families are deliberately not owned by this collector.
	conformance.Check(t, conformance.Case{Collector: buildDisk(t, collectors.DefaultDiskstatsConfig), Families: diskFamilies})
}

func diskInput(c agentless.Collector, text string) agentless.Input {
	read := c.Reads()[0]
	return agentless.Input{read.ID: {Read: read, Output: []byte(text)}}
}

func diskMetrics(t *testing.T, c agentless.Collector, text string) map[string]map[string]*dto.Metric {
	t.Helper()
	ch := make(chan prometheus.Metric, 1024)
	require.NoError(t, c.Update(agentless.Target{}, diskInput(c, text), ch))
	close(ch)
	out := map[string]map[string]*dto.Metric{}
	for metric := range ch {
		m := new(dto.Metric)
		require.NoError(t, metric.Write(m))
		// Match actual descriptors rather than constructing a parallel exporter.
		matched := false
		for _, name := range diskFamilies {
			if strings.Contains(metric.Desc().String(), `fqName: "`+name+`"`) {
				if out[name] == nil {
					out[name] = map[string]*dto.Metric{}
				}
				require.Len(t, m.Label, 1)
				require.Equal(t, "device", m.Label[0].GetName())
				out[name][m.Label[0].GetValue()] = m
				matched = true
			}
		}
		require.True(t, matched, "unexpected metric: %s", metric.Desc())
	}
	return out
}

func TestDiskstatsColumnsAndScaling(t *testing.T) {
	c := buildDisk(t, collectors.DiskstatsConfig{})
	fields := "1 2 3 4005 5 6 7 8009 9 10011 11012 12 13 14 15016 16 17018"
	for _, count := range []int{11, 15, 17, 18} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			t.Parallel()
			columns := strings.Fields(fields)
			if count == 18 {
				columns = append(columns, "999")
			}
			actual := diskMetrics(t, c, "8 0 sda "+strings.Join(columns[:count], " ")+"\n")
			expected := []float64{1, 2, 1536, 4.005, 5, 6, 3584, 8.009, 9, 10.011, 11.012, 12, 13, 14, 15.016, 16, 17.018}
			require.Len(t, actual, min(count, 17))
			for i, name := range diskFamilies[:min(count, 17)] {
				m := actual[name]["sda"]
				require.NotNil(t, m, name)
				if i == 8 {
					require.NotNil(t, m.Gauge)
					require.Equal(t, expected[i], m.Gauge.GetValue())
				} else {
					require.NotNil(t, m.Counter)
					require.InDelta(t, expected[i], m.Counter.GetValue(), 1e-12)
				}
			}
		})
	}
}

func TestDiskstatsDeviceFilters(t *testing.T) {
	devices := []string{"ram0", "loop12", "fd0", "hda1", "sda12", "vda2", "xvda3", "nvme0n1p2", "sda", "nvme0n1", "dm-0", "mmcblk0p1", "zram0"}
	var input strings.Builder
	for _, device := range devices {
		fmt.Fprintf(&input, "8 0 %s 1 2 3 4 5 6 7 8 9 10 11\n", device)
	}
	for _, tc := range []struct {
		name string
		cfg  collectors.DiskstatsConfig
		want []string
	}{
		{"default", collectors.DefaultDiskstatsConfig, devices[8:]},
		{"include overrides default", collectors.DiskstatsConfig{DeviceInclude: "^sda12$", DeviceExclude: collectors.DefaultDiskstatsConfig.DeviceExclude}, []string{"sda12"}},
		{"exclude", collectors.DiskstatsConfig{DeviceExclude: "^(sda|zram0)$"}, []string{"ram0", "loop12", "fd0", "hda1", "sda12", "vda2", "xvda3", "nvme0n1p2", "nvme0n1", "dm-0", "mmcblk0p1"}},
		{"empty", collectors.DiskstatsConfig{}, devices},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actual := diskMetrics(t, buildDisk(t, tc.cfg), input.String())
			for _, name := range diskFamilies[:11] {
				require.ElementsMatch(t, tc.want, diskDeviceNames(actual[name]))
			}
		})
	}
}

func diskDeviceNames(metrics map[string]*dto.Metric) []string {
	names := make([]string, 0, len(metrics))
	for name := range metrics {
		names = append(names, name)
	}
	return names
}

// This pipeline test uses a synthetic Linux row, not a node_exporter oracle;
// the separate conformance test supplies the pinned exporter comparison.
func TestDiskstatsScraperPipeline(t *testing.T) {
	c := buildDisk(t, collectors.DefaultDiskstatsConfig)
	read := c.Reads()[0]
	runner := &agentlesstest.FakeRunner{Results: map[string]agentless.Result{
		read.ID: {Read: read, Output: []byte("8 0 sda 1 2 3 4 5 6 7 8 9 10 11 12 13 14 1500 16 1700\n")},
	}}
	scraper, err := agentless.NewScraper(runner, []agentless.Collector{c}, util.TestLogger(t))
	require.NoError(t, err)
	metrics, err := scraper.Scrape(t.Context(), agentless.Target{Address: "fixture"})
	require.NoError(t, err)
	require.Equal(t, 1, runner.Calls())
	require.NoError(t, testutil.CollectAndCompare(metrics, strings.NewReader(`
# HELP node_disk_discarded_sectors_total The total number of sectors discarded successfully.
# TYPE node_disk_discarded_sectors_total counter
node_disk_discarded_sectors_total{device="sda"} 14
# HELP node_disk_flush_requests_time_seconds_total This is the total number of seconds spent by all flush requests.
# TYPE node_disk_flush_requests_time_seconds_total counter
node_disk_flush_requests_time_seconds_total{device="sda"} 1.7
# HELP node_scrape_collector_success node_exporter: Whether a collector succeeded.
# TYPE node_scrape_collector_success gauge
node_scrape_collector_success{collector="diskstats"} 1
`), "node_disk_discarded_sectors_total", "node_disk_flush_requests_time_seconds_total", "node_scrape_collector_success"))
}

func TestDiskstatsInvalidRegex(t *testing.T) {
	for _, cfg := range []collectors.DiskstatsConfig{{DeviceInclude: "["}, {DeviceExclude: "["}} {
		configs := collectors.DefaultConfigs()
		configs.Diskstats = cfg
		_, err := collectors.Build([]string{"diskstats"}, configs, util.TestLogger(t))
		require.Error(t, err)
	}
	// An ignored exclusion need not be a valid regex.
	buildDisk(t, collectors.DiskstatsConfig{DeviceInclude: "sda", DeviceExclude: "["})
}

func TestDiskstatsBadInput(t *testing.T) {
	c := buildDisk(t, collectors.DiskstatsConfig{})
	for _, text := range []string{"8 0 sda 1 2", "x 0 sda 1 2 3 4 5 6 7 8 9 10 11", "8 0 sda 1 2 3 4 5 6 7 8 9 10 -1", "8 0 sda 1 2 3 4 5 6 7 8 9 10 nope", "8 0 sda 18446744073709551616 2 3 4 5 6 7 8 9 10 11", strings.Repeat("x", 70000)} {
		require.Error(t, c.Update(agentless.Target{}, diskInput(c, text), make(chan prometheus.Metric, 32)))
	}
	require.Empty(t, diskMetrics(t, c, "\n \t\n"))
	for _, result := range []agentless.Result{{ExitStatus: 1}, {NotExist: true}, {Truncated: true}, {TimedOut: true}} {
		read := c.Reads()[0]
		result.Read = read
		require.Error(t, c.Update(agentless.Target{}, agentless.Input{read.ID: result}, make(chan prometheus.Metric, 32)))
	}
	require.Error(t, c.Update(agentless.Target{}, nil, make(chan prometheus.Metric, 32)))
}
