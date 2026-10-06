// Copyright 2019 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collectors

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"slices"
	"strconv"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	Register(Registration{Name: "softnet", OS: "linux", DefaultEnabled: true, Factory: newSoftnetCollector})
}

// Seven fixed families leave at most 2857 CPU rows within the frozen 20000
// series budget. CPU labels are decimal uint32 (at most ten bytes), and the
// family count is fixed below 500. Bound rows before retaining target data.
const maxSoftnetCPUs = 20000 / 7

var softnetMetrics = [...]struct{ name, help string }{
	{"processed_total", "Number of processed packets"},
	{"dropped_total", "Number of dropped packets"},
	{"times_squeezed_total", "Number of times processing packets ran out of quota"},
	{"cpu_collision_total", "Number of collision occur while obtaining device lock while transmitting"},
	{"received_rps_total", "Number of times cpu woken up received_rps"},
	{"flow_limit_count_total", "Number of times flow limit has been reached"},
	{"backlog_len", "Softnet backlog status"},
}

type softnetCollector struct{ descs [7]*prometheus.Desc }

func newSoftnetCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	c := &softnetCollector{}
	for i, metric := range softnetMetrics {
		c.descs[i] = prometheus.NewDesc(agentless.Namespace+"_softnet_"+metric.name, metric.help, []string{"cpu"}, nil)
	}
	return c, nil
}

func (c *softnetCollector) Name() string { return "softnet" }
func (c *softnetCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/net/softnet_stat")}
}

func (c *softnetCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	read := c.Reads()[0]
	result := in[read.ID]
	if result.NotExist && !result.TimedOut && !result.Truncated {
		return nil
	}
	output, err := in.Output(read)
	if err != nil {
		return fmt.Errorf("softnet: %w", err)
	}
	// Parse and validate the whole bounded snapshot before emitting anything.
	rows, err := parseSoftnetStats(output)
	if err != nil {
		return err
	}
	for _, row := range rows {
		cpu := strconv.FormatUint(uint64(row[7]), 10)
		for i, desc := range c.descs {
			kind := prometheus.CounterValue
			if i == 6 {
				kind = prometheus.GaugeValue
			}
			ch <- targetMetric(desc, kind, float64(row[i]), cpu)
		}
	}
	return nil
}

// Column semantics follow procfs v0.16.1 net_softnet.go: columns 0,1,2,8,
// 9,10 are counters; 11 and 12 supply backlog and CPU index only for widths
// >=13. Older kernels use the row index. Unlike upstream, scanner errors and
// empty files are rejected rather than silently returning partial snapshots.
func parseSoftnetStats(output []byte) ([][8]uint32, error) {
	scanner := bufio.NewScanner(bytes.NewReader(output))
	// Fixed scanner storage avoids growth allocations on hostile long lines.
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	rows := make([][8]uint32, 0, maxSoftnetCPUs)
	var indices [maxSoftnetCPUs]uint32
	for scanner.Scan() {
		if len(rows) == maxSoftnetCPUs {
			return nil, fmt.Errorf("softnet: CPU limit exceeded (%d)", maxSoftnetCPUs)
		}
		var columns [13]uint32
		width := 0
		for field := range bytes.FieldsSeq(scanner.Bytes()) {
			value, err := strconv.ParseUint(string(field), 16, 32)
			if err != nil {
				return nil, fmt.Errorf("softnet: invalid column %d: %w", width, err)
			}
			if width < len(columns) {
				columns[width] = uint32(value)
			}
			width++
		}
		if width < 9 {
			return nil, fmt.Errorf("softnet: row has %d columns, want at least 9", width)
		}
		row := [8]uint32{columns[0], columns[1], columns[2], columns[8], columns[9], columns[10], 0, uint32(len(rows))}
		if width >= 13 {
			row[6], row[7] = columns[11], columns[12]
		}
		indices[len(rows)] = row[7]
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("softnet: scan: %w", err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("softnet: no CPU rows")
	}
	slices.Sort(indices[:len(rows)])
	for i := 1; i < len(rows); i++ {
		if indices[i] == indices[i-1] {
			return nil, fmt.Errorf("softnet: duplicate CPU index %d", indices[i])
		}
	}
	return rows, nil
}
