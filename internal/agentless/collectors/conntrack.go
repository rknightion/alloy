// Copyright 2015 The Prometheus Authors
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
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
)

func init() {
	Register(Registration{Name: "conntrack", OS: "linux", DefaultEnabled: false, Factory: newConntrackCollector})
}

// Names, help and gauge types match node_exporter's conntrack_linux.go.
var conntrackMetrics = [...]struct{ name, help string }{
	{"entries", "Number of currently allocated flow entries for connection tracking."},
	{"entries_limit", "Maximum size of connection tracking table."},
	{"stat_found", "Number of searched entries which were successful."},
	{"stat_invalid", "Number of packets seen which can not be tracked."},
	{"stat_ignore", "Number of packets seen which are already connected to a conntrack entry."},
	{"stat_insert", "Number of entries inserted into the list."},
	{"stat_insert_failed", "Number of entries for which list insertion was attempted but failed."},
	{"stat_drop", "Number of packets dropped due to conntrack failure."},
	{"stat_early_drop", "Number of dropped conntrack entries to make room for new ones, if maximum table size was reached."},
	{"stat_search_restart", "Number of conntrack table lookups which had to be restarted due to hashtable resizes."},
}

const conntrackHeader = "entries searched found new invalid ignore delete delete_list insert insert_failed drop early_drop icmp_error expect_new expect_create expect_delete search_restart"

// These positions match procfs.ConntrackStatEntry, including the optional
// search_restart column added in Linux 2.6.35.
var conntrackStatColumns = [...]int{2, 4, 5, 8, 9, 10, 11, 16}

type conntrackCollector struct {
	descs [10]*prometheus.Desc
}

func newConntrackCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	c := &conntrackCollector{}
	for i, metric := range conntrackMetrics {
		c.descs[i] = prometheus.NewDesc(agentless.Namespace+"_nf_conntrack_"+metric.name, metric.help, nil, nil)
	}
	return c, nil
}

// Name implements agentless.Collector.
func (c *conntrackCollector) Name() string { return "conntrack" }

// Reads implements agentless.Collector.
func (c *conntrackCollector) Reads() []agentless.Read {
	return []agentless.Read{
		agentless.FileRead("/proc/sys/net/netfilter/nf_conntrack_count"),
		agentless.FileRead("/proc/sys/net/netfilter/nf_conntrack_max"),
		agentless.FileRead("/proc/net/stat/nf_conntrack"),
	}
}

// Update implements agentless.Collector.
func (c *conntrackCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	// Validate all present reads before emission. Missing optional files suppress
	// only their families. Retention is fixed regardless of the CPU row count.
	var values [10]uint64
	var present [10]bool
	for i, read := range c.Reads() {
		res, ok := in[read.ID]
		if ok && res.NotExist && !res.TimedOut && !res.Truncated {
			continue
		}
		output, err := in.Output(read)
		if err != nil {
			return fmt.Errorf("conntrack: %w", err)
		}
		if i < 2 {
			value, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
			if err != nil {
				return fmt.Errorf("conntrack: %s: %w", read.Path, err)
			}
			values[i], present[i] = value, true
			continue
		}
		stats, err := parseConntrackStats(output)
		if err != nil {
			return err
		}
		for j, value := range stats {
			values[j+2], present[j+2] = value, true
		}
	}
	for i, value := range values {
		if present[i] {
			ch <- targetMetric(c.descs[i], prometheus.GaugeValue, float64(value))
		}
	}
	return nil
}

func parseConntrackStats(output []byte) ([8]uint64, error) {
	var totals [8]uint64
	scanner := bufio.NewScanner(bytes.NewReader(output))
	if !scanner.Scan() {
		return totals, fmt.Errorf("conntrack: missing statistics header")
	}
	// Accept both supported kernel layouts, but not arbitrary/empty headers.
	header := strings.Join(strings.Fields(scanner.Text()), " ")
	// Linux renamed two unused columns to clashres and chainlength. Their
	// positions and the eight exported statistics are unchanged.
	header = strings.Replace(header, " clashres ", " searched ", 1)
	header = strings.Replace(header, " chainlength ", " delete_list ", 1)
	if header != conntrackHeader && header != strings.TrimSuffix(conntrackHeader, " search_restart") {
		return totals, fmt.Errorf("conntrack: malformed statistics header")
	}
	columns := 17
	if header != conntrackHeader {
		columns = 16
	}
	for scanner.Scan() {
		var row [17]uint64
		n := 0
		for field := range bytes.FieldsSeq(scanner.Bytes()) {
			if n == columns {
				return totals, fmt.Errorf("conntrack: too many statistics columns")
			}
			value, err := strconv.ParseUint(string(field), 16, 64)
			if err != nil {
				return totals, fmt.Errorf("conntrack: invalid statistics column %d: %w", n, err)
			}
			row[n] = value
			n++
		}
		if n != columns {
			return totals, fmt.Errorf("conntrack: statistics row has %d columns, want %d", n, columns)
		}
		for i, column := range conntrackStatColumns {
			// uint64 addition deliberately matches upstream aggregation semantics.
			totals[i] += row[column]
		}
	}
	if err := scanner.Err(); err != nil {
		return totals, fmt.Errorf("conntrack: scan statistics: %w", err)
	}
	return totals, nil
}
