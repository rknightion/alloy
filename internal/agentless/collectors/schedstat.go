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
	"strconv"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	Register(Registration{Name: "schedstat", OS: "linux", DefaultEnabled: true, Factory: newSchedstatCollector})
}

// Three fixed families, with at most 20,000 series and 4,096 bytes per label.
// Bound ignored domain/header lines too, before parsing or retaining CPU rows.
const (
	maxSchedstatCPUs       = 20000 / 3
	maxSchedstatLines      = 20000
	maxSchedstatLabelBytes = 4096
)

var schedstatMetrics = [...]struct{ name, help string }{
	{"running_seconds_total", "Number of seconds CPU spent running a process."},
	{"waiting_seconds_total", "Number of seconds spent by processing waiting for this CPU."},
	{"timeslices_total", "Number of timeslices executed by CPU."},
}

type schedstatCollector struct{ descs [3]*prometheus.Desc }

func newSchedstatCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	c := &schedstatCollector{}
	for i, m := range schedstatMetrics {
		c.descs[i] = prometheus.NewDesc(agentless.Namespace+"_schedstat_"+m.name, m.help, []string{"cpu"}, nil)
	}
	return c, nil
}
func (c *schedstatCollector) Name() string { return "schedstat" }
func (c *schedstatCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/schedstat")}
}

func (c *schedstatCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	read := c.Reads()[0]
	if r, ok := in[read.ID]; ok && r.NotExist && !r.TimedOut && !r.Truncated {
		return nil
	}
	output, err := in.Output(read)
	if err != nil {
		return fmt.Errorf("schedstat: %w", err)
	}
	rows, err := parseSchedstat(output)
	if err != nil {
		return err
	}
	for _, row := range rows {
		for i, value := range row.values {
			v := float64(value)
			if i < 2 {
				v /= 1e9
			}
			ch <- targetMetric(c.descs[i], prometheus.CounterValue, v, row.cpu)
		}
	}
	return nil
}

type schedstatCPU struct {
	cpu    string
	values [3]uint64
}

// The procfs parser selects the last three of nine CPU statistics and ignores
// domain statistics. Unlike its permissive regexp, malformed CPU rows fail the
// whole snapshot, so no partial metrics escape. FieldsSeq and Scanner bound
// allocations even for hostile lines and stop before retaining excess CPUs.
func parseSchedstat(output []byte) ([]schedstatCPU, error) {
	var rows []schedstatCPU
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	lines := 0
	for scanner.Scan() {
		if lines == maxSchedstatLines {
			return nil, fmt.Errorf("schedstat: line limit exceeded (%d)", maxSchedstatLines)
		}
		lines++
		var row schedstatCPU
		count := 0
		const (
			unknownRow = iota
			cpuRow
			domainRow
			headerRow
		)
		kind := unknownRow
		for field := range bytes.FieldsSeq(scanner.Bytes()) {
			if count == 0 {
				switch {
				case bytes.HasPrefix(field, []byte("cpu")):
					if len(rows) == maxSchedstatCPUs {
						return nil, fmt.Errorf("schedstat: CPU limit exceeded (%d)", maxSchedstatCPUs)
					}
					label := field[3:]
					if len(label) == 0 || len(label) > maxSchedstatLabelBytes {
						return nil, fmt.Errorf("schedstat: invalid CPU label length")
					}
					for _, b := range label {
						if b < '0' || b > '9' {
							return nil, fmt.Errorf("schedstat: invalid CPU label")
						}
					}
					row.cpu = string(label)
					if seen[row.cpu] {
						return nil, fmt.Errorf("schedstat: duplicate CPU")
					}
					kind = cpuRow
				case bytes.HasPrefix(field, []byte("domain")):
					// Domain layouts vary by kernel version and are not exported upstream.
					kind = domainRow
				case bytes.Equal(field, []byte("version")), bytes.Equal(field, []byte("timestamp")):
					kind = headerRow
				default:
					return nil, fmt.Errorf("schedstat: unrecognized row")
				}
			} else if kind != domainRow {
				if (kind == cpuRow && count > 9) || (kind == headerRow && count > 1) {
					return nil, fmt.Errorf("schedstat: excess columns")
				}
				// Bound conversion/error allocation independently of the scanner's line cap.
				if len(field) > 20 || bytes.HasPrefix(field, []byte("+")) {
					return nil, fmt.Errorf("schedstat: invalid numeric column")
				}
				value, err := strconv.ParseUint(string(field), 10, 64)
				if err != nil {
					return nil, fmt.Errorf("schedstat: invalid numeric column")
				}
				if kind == cpuRow && count >= 7 {
					row.values[count-7] = value
				}
			}
			count++
		}
		if kind == cpuRow {
			if count != 10 {
				return nil, fmt.Errorf("schedstat: missing CPU columns")
			}
			seen[row.cpu] = true
			rows = append(rows, row)
		} else if kind == headerRow && count != 2 || kind == unknownRow {
			return nil, fmt.Errorf("schedstat: malformed row")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("schedstat: scan: %w", err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("schedstat: missing CPU statistics")
	}
	return rows, nil
}
