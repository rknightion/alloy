package collectors

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
)

func init() {
	Register(Registration{Name: "diskstats", OS: "linux", DefaultEnabled: true, Factory: newDiskstatsCollector})
}

// DiskstatsConfig holds the diskstats collector options. Both fields are
// regular expressions. A non-empty DeviceInclude takes precedence and
// DeviceExclude is then ignored, so setting only DeviceInclude over the
// defaults works.
type DiskstatsConfig struct {
	DeviceExclude string
	DeviceInclude string
}

// DefaultDiskstatsConfig matches node_exporter's defaults.
var DefaultDiskstatsConfig = DiskstatsConfig{
	DeviceExclude: `^(ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\d+n\d+p)\d+$`,
}

type diskstatsCollector struct {
	deviceFilter *regexp.Regexp
	include      bool
	descs        []*prometheus.Desc
}

// The order follows /proc/diskstats, not alphabetical metric order. Sector
// counts for reads/writes are always 512-byte sectors; discarded sectors stay
// in sectors to match node_exporter. Kernel times are milliseconds.
var diskstatsFields = []struct {
	name   string
	help   string
	factor float64
}{
	{"reads_completed_total", "The total number of reads completed successfully.", 1},
	{"reads_merged_total", "The total number of reads merged.", 1},
	{"read_bytes_total", "The total number of bytes read successfully.", 512},
	{"read_time_seconds_total", "The total number of seconds spent by all reads.", 0.001},
	{"writes_completed_total", "The total number of writes completed successfully.", 1},
	{"writes_merged_total", "The number of writes merged.", 1},
	{"written_bytes_total", "The total number of bytes written successfully.", 512},
	{"write_time_seconds_total", "This is the total number of seconds spent by all writes.", 0.001},
	{"io_now", "The number of I/Os currently in progress.", 1},
	{"io_time_seconds_total", "Total seconds spent doing I/Os.", 0.001},
	{"io_time_weighted_seconds_total", "The weighted # of seconds spent doing I/Os.", 0.001},
	{"discards_completed_total", "The total number of discards completed successfully.", 1},
	{"discards_merged_total", "The total number of discards merged.", 1},
	{"discarded_sectors_total", "The total number of sectors discarded successfully.", 1},
	{"discard_time_seconds_total", "This is the total number of seconds spent by all discards.", 0.001},
	{"flush_requests_total", "The total number of flush requests completed successfully", 1},
	{"flush_requests_time_seconds_total", "This is the total number of seconds spent by all flush requests.", 0.001},
}

func newDiskstatsCollector(cfg Configs, _ *slog.Logger) (agentless.Collector, error) {
	c := &diskstatsCollector{include: cfg.Diskstats.DeviceInclude != ""}
	pattern := cfg.Diskstats.DeviceExclude
	if c.include {
		pattern = cfg.Diskstats.DeviceInclude
	}
	if pattern != "" {
		filter, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("diskstats device filter: %w", err)
		}
		c.deviceFilter = filter
	}
	for _, field := range diskstatsFields {
		c.descs = append(c.descs, prometheus.NewDesc(prometheus.BuildFQName(agentless.Namespace, "disk", field.name), field.help, []string{"device"}, nil))
	}
	return c, nil
}

// Name implements agentless.Collector.
func (c *diskstatsCollector) Name() string { return "diskstats" }

// Reads implements agentless.Collector.
func (c *diskstatsCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/diskstats")}
}

// Update implements agentless.Collector.
func (c *diskstatsCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	read := c.Reads()[0]
	if in[read.ID].NotExist {
		return fmt.Errorf("diskstats: %s does not exist", read.Path)
	}
	output, err := in.Output(read)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for line := 1; scanner.Scan(); line++ {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 14 {
			return fmt.Errorf("diskstats line %d: expected at least 14 columns, got %d", line, len(fields))
		}
		for _, field := range fields[:2] {
			if _, err := strconv.ParseUint(field, 10, 32); err != nil {
				return fmt.Errorf("diskstats line %d: invalid device number: %w", line, err)
			}
		}
		values := make([]uint64, min(len(fields)-3, len(diskstatsFields)))
		for i := range values {
			value, err := strconv.ParseUint(fields[i+3], 10, 64)
			if err != nil {
				return fmt.Errorf("diskstats line %d column %d: %w", line, i+4, err)
			}
			values[i] = value
		}
		device := fields[2]
		if c.deviceFilter != nil && c.deviceFilter.MatchString(device) != c.include {
			continue
		}
		// Emit only columns present on this kernel. Future appended columns
		// are ignored, never mistaken for an existing statistic.
		for i, value := range values {
			kind := prometheus.CounterValue
			if i == 8 {
				kind = prometheus.GaugeValue
			}
			ch <- prometheus.MustNewConstMetric(c.descs[i], kind, float64(value)*diskstatsFields[i].factor, device)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("diskstats: scan: %w", err)
	}
	return nil
}
