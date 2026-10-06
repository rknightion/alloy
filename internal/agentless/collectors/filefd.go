package collectors

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
)

func init() {
	Register(Registration{Name: "filefd", OS: "linux", DefaultEnabled: false, Factory: newFilefdCollector})
}

type filefdCollector struct{}

func newFilefdCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &filefdCollector{}, nil
}
func (*filefdCollector) Name() string { return "filefd" }
func (*filefdCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/sys/fs/file-nr")}
}

// Update validates the complete snapshot before emitting either family.
func (c *filefdCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	read := c.Reads()[0]
	if result, ok := in[read.ID]; ok && result.NotExist && !result.TimedOut && !result.Truncated {
		return nil
	}
	output, err := in.Output(read)
	if err != nil {
		return err
	}
	fields := strings.Fields(string(output))
	if len(fields) != 3 {
		return fmt.Errorf("filefd: expected three fields")
	}
	var values [3]uint64
	for i, field := range fields {
		values[i], err = strconv.ParseUint(field, 10, 64)
		if err != nil {
			return fmt.Errorf("filefd: invalid field %d: %w", i, err)
		}
	}
	// Linux 2.6 and later do not use the middle (unused descriptors) field.
	for _, field := range []struct {
		name  string
		value uint64
	}{{"allocated", values[0]}, {"maximum", values[2]}} {
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc(agentless.Namespace+"_filefd_"+field.name, "File descriptor statistics: "+field.name+".", nil, nil), prometheus.GaugeValue, float64(field.value))
	}
	return nil
}
