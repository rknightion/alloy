// Copyright 2017 The Prometheus Authors
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
	"bytes"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	Register(Registration{Name: "bcache", OS: "linux", DefaultEnabled: false, Factory: newBcacheCollector})
}

const (
	bcacheRoot = "/sys/fs/bcache"
	bcacheNext = "next"
)

// Port of the pinned node_exporter's default (StatsWithoutPriority) surface.
// priority_stats_unused_percent and priority_stats_metadata_percent are omitted:
// priority_stats is an opt-in, expensive upstream read. The procfs parser also
// reads cache-set stats_total/stats_five_minute and backing stats_five_minute,
// but node_exporter exports none of these, so they need no remote reads.
// Read sets below cover cache-set attributes (including internal), backing
// dirty_data/writeback_rate_debug/stats_total, and cache device attributes.
type bcacheSpec struct {
	attr, family, help string
	kind               prometheus.ValueType
	scale              float64
	group              int // 0 cache set, 1 backing device, 2 cache device
}

var bcacheSpecs = [...]bcacheSpec{
	{"average_key_size", "average_key_size_sectors", "Average data per key in the btree (sectors).", prometheus.GaugeValue, 1, 0},
	{"btree_cache_size", "btree_cache_size_bytes", "Amount of memory currently used by the btree cache.", prometheus.GaugeValue, 1, 0},
	{"cache_available_percent", "cache_available_percent", "Percentage of cache device without dirty data, usable for writeback (may contain clean cached data).", prometheus.GaugeValue, 1, 0},
	{"congested", "congested", "Congestion.", prometheus.GaugeValue, 1, 0},
	{"root_usage_percent", "root_usage_percent", "Percentage of the root btree node in use (tree depth increases if too high).", prometheus.GaugeValue, 1, 0},
	{"tree_depth", "tree_depth", "Depth of the btree.", prometheus.GaugeValue, 1, 0},
	{"internal/active_journal_entries", "active_journal_entries", "Number of journal entries that are newer than the index.", prometheus.GaugeValue, 1, 0},
	{"internal/btree_nodes", "btree_nodes", "Total nodes in the btree.", prometheus.GaugeValue, 1, 0},
	// Preserve upstream's 1e-9 conversion despite the sysfs filename's _us suffix.
	{"internal/btree_read_average_duration_us", "btree_read_average_duration_seconds", "Average btree read duration.", prometheus.GaugeValue, 1e-9, 0},
	{"internal/cache_read_races", "cache_read_races_total", "Counts instances where while data was being read from the cache, the bucket was reused and invalidated - i.e. where the pointer was stale after the read completed.", prometheus.CounterValue, 1, 0},
	{"dirty_data", "dirty_data_bytes", "Amount of dirty data for this backing device in the cache.", prometheus.GaugeValue, 1, 1},
	{"target", "dirty_target_bytes", "Current dirty data target threshold for this backing device in bytes.", prometheus.GaugeValue, 1, 1},
	{"rate", "writeback_rate", "Current writeback rate for this backing device in bytes.", prometheus.GaugeValue, 1, 1},
	{"proportional", "writeback_rate_proportional_term", "Current result of proportional controller, part of writeback rate", prometheus.GaugeValue, 1, 1},
	{"integral", "writeback_rate_integral_term", "Current result of integral controller, part of writeback rate", prometheus.GaugeValue, 1, 1},
	{"change", "writeback_change", "Last writeback rate change step for this backing device.", prometheus.GaugeValue, 1, 1},
	{"stats_total/bypassed", "bypassed_bytes_total", "Amount of IO (both reads and writes) that has bypassed the cache.", prometheus.CounterValue, 1, 1},
	{"stats_total/cache_hits", "cache_hits_total", "Hits counted per individual IO as bcache sees them.", prometheus.CounterValue, 1, 1},
	{"stats_total/cache_misses", "cache_misses_total", "Misses counted per individual IO as bcache sees them.", prometheus.CounterValue, 1, 1},
	{"stats_total/cache_bypass_hits", "cache_bypass_hits_total", "Hits for IO intended to skip the cache.", prometheus.CounterValue, 1, 1},
	{"stats_total/cache_bypass_misses", "cache_bypass_misses_total", "Misses for IO intended to skip the cache.", prometheus.CounterValue, 1, 1},
	{"stats_total/cache_miss_collisions", "cache_miss_collisions_total", "Instances where data insertion from cache miss raced with write (data already present).", prometheus.CounterValue, 1, 1},
	{"stats_total/cache_readaheads", "cache_readaheads_total", "Count of times readahead occurred.", prometheus.CounterValue, 1, 1},
	{"io_errors", "io_errors", "Number of errors that have occurred, decayed by io_error_halflife.", prometheus.GaugeValue, 1, 2},
	{"metadata_written", "metadata_written_bytes_total", "Sum of all non data writes (btree writes and all other metadata).", prometheus.CounterValue, 1, 2},
	{"written", "written_bytes_total", "Sum of all data that has been written to the cache.", prometheus.CounterValue, 1, 2},
}

type bcacheCollector struct {
	desc [len(bcacheSpecs)]*prometheus.Desc
}

var _ agentless.DeepExpander = (*bcacheCollector)(nil)

func newBcacheCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	c := &bcacheCollector{}
	for i, s := range bcacheSpecs {
		labels := []string{"uuid"}
		if s.group == 1 {
			labels = append(labels, "backing_device")
		}
		if s.group == 2 {
			labels = append(labels, "cache_device")
		}
		c.desc[i] = prometheus.NewDesc(agentless.Namespace+"_bcache_"+s.family, s.help, labels, nil)
	}
	return c, nil
}
func (*bcacheCollector) Name() string { return "bcache" }
func (*bcacheCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.CommandRead("ls", "-1", bcacheRoot)}
}
func bcacheList(uuid string) agentless.Read {
	return agentless.CommandRead("ls", "-1", bcacheRoot+"/"+uuid)
}
func bcacheFile(uuid, device, attr string) agentless.Read {
	path := bcacheRoot + "/" + uuid + "/"
	if device != "" {
		path += device + "/"
	}
	return agentless.FileRead(path + attr)
}
func bcacheOutput(in agentless.Input, read agentless.Read) ([]byte, bool, error) {
	if err := read.Validate(); err != nil {
		return nil, false, err
	}
	r := in[read.ID]
	if r.NotExist && !r.TimedOut && !r.Truncated {
		return nil, false, nil
	}
	out, err := in.Output(read)
	return out, err == nil, err
}
func bcacheDevice(row []byte) bool {
	for _, prefix := range []string{"bdev", "cache"} {
		if bytes.HasPrefix(row, []byte(prefix)) && len(row) > len(prefix) && row[len(prefix)] >= '0' && row[len(prefix)] <= '9' {
			return btrfsDevice(row)
		}
	}
	return false
}
func (c *bcacheCollector) sets(in agentless.Input) ([]string, error) {
	return bcacheNames(in, c.Reads()[0], func(row []byte) bool { return bytes.ContainsRune(row, '-') && btrfsDevice(row) }, agentless.MaxDeepListings)
}

// Bound all rows, including ignored entries, before allocating strings. Reject
// the entire expansion rather than silently scraping a prefix of the target.
func bcacheNames(in agentless.Input, read agentless.Read, accept func([]byte) bool, limit int) ([]string, error) {
	out, _, err := bcacheOutput(in, read)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	if out[len(out)-1] != '\n' {
		return nil, fmt.Errorf("bcache: unterminated listing")
	}
	var names []string
	rows := 0
	for row := range bytes.SplitSeq(out[:len(out)-1], []byte{'\n'}) {
		rows++
		if rows > agentless.MaxExpandedReads || len(row) > 4096 || len(row) == 0 {
			return nil, fmt.Errorf("bcache: listing limit exceeded")
		}
		if !accept(row) {
			continue
		}
		if len(names) >= limit {
			return nil, fmt.Errorf("bcache: expansion limit exceeded")
		}
		name := string(row)
		for _, prior := range names {
			if prior == name {
				return nil, fmt.Errorf("bcache: duplicate entry")
			}
		}
		names = append(names, name)
	}
	return names, nil
}
func (c *bcacheCollector) Expand(_ agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	sets, err := c.sets(in)
	if err != nil {
		return nil, err
	}
	var reads []agentless.Read
	for _, uuid := range sets {
		reads = append(reads, bcacheList(uuid))
		for _, s := range bcacheSpecs {
			if s.group == 0 {
				reads = append(reads, bcacheFile(uuid, "", s.attr))
			}
		}
	}
	for _, r := range reads {
		if err := r.Validate(); err != nil {
			return nil, err
		}
	}
	return reads, nil
}
func (c *bcacheCollector) ExpandDeep(target agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	sets, err := c.sets(in)
	if err != nil {
		return nil, err
	}
	second, err := c.Expand(target, in)
	if err != nil {
		return nil, err
	}
	var reads []agentless.Read
	for _, uuid := range sets {
		devices, err := bcacheNames(in, bcacheList(uuid), bcacheDevice, (agentless.MaxExpandedReads-len(second)-len(reads))/3)
		if err != nil {
			return nil, err
		}
		for _, dev := range devices {
			attrs := []string{"io_errors", "metadata_written", "written"}
			if strings.HasPrefix(dev, "bdev") {
				attrs = []string{"dirty_data", "writeback_rate_debug", "stats_total/bypassed", "stats_total/cache_hits", "stats_total/cache_misses", "stats_total/cache_bypass_hits", "stats_total/cache_bypass_misses", "stats_total/cache_miss_collisions", "stats_total/cache_readaheads"}
			}
			if len(second)+len(reads)+len(attrs) > agentless.MaxExpandedReads {
				return nil, fmt.Errorf("bcache: expanded read limit exceeded")
			}
			for _, attr := range attrs {
				r := bcacheFile(uuid, dev, attr)
				if err := r.Validate(); err != nil {
					return nil, err
				}
				reads = append(reads, r)
			}
		}
	}
	return reads, nil
}

// bch_hprint's fractional digits are hundredths of 1024, not decimal
// fractions: upstream deliberately treats .1 differently from .10.
func bcacheNumber(raw []byte, signed bool) (float64, error) {
	if len(raw) > 64 {
		return 0, fmt.Errorf("bcache: numeric input too long")
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || len(raw) > 32 {
		return 0, fmt.Errorf("bcache: numeric length")
	}
	negative := raw[0] == '-'
	if negative {
		if !signed {
			return 0, fmt.Errorf("bcache: negative unsigned value")
		}
		raw = raw[1:]
	}
	if len(raw) == 0 {
		return 0, fmt.Errorf("bcache: empty number")
	}
	mul := 1.0
	if suffix := raw[len(raw)-1]; suffix < '0' || suffix > '9' {
		idx := strings.IndexByte("kMGTPEZY", suffix)
		if idx < 0 {
			return 0, fmt.Errorf("bcache: invalid suffix")
		}
		mul = math.Pow(1024, float64(idx+1))
		raw = raw[:len(raw)-1]
	}
	for _, b := range raw {
		if (b < '0' || b > '9') && b != '.' {
			return 0, fmt.Errorf("bcache: invalid number")
		}
	}
	value, err := strconv.ParseFloat(string(raw), 64)
	if mul != 1 {
		parts := bytes.Split(raw, []byte{'.'})
		if len(parts) > 2 {
			return 0, fmt.Errorf("bcache: invalid fraction")
		}
		if len(parts) == 2 {
			whole, e1 := strconv.ParseFloat(string(parts[0]), 64)
			frac, e2 := strconv.ParseFloat(string(parts[1]), 64)
			if e1 != nil || e2 != nil {
				return 0, fmt.Errorf("bcache: invalid fraction")
			}
			value = whole + frac/10.24
		}
	}
	value *= mul
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value >= math.Exp2(64) || signed && value >= math.Exp2(63) {
		return 0, fmt.Errorf("bcache: numeric overflow or malformed value")
	}
	value = float64(uint64(value))
	if negative {
		value = -value
	}
	return value, nil
}
func bcacheDebug(out []byte) (map[string]float64, error) {
	if len(out) > 4096 {
		return nil, fmt.Errorf("bcache: debug file too long")
	}
	values := map[string]float64{}
	rows := 0
	for row := range bytes.SplitSeq(out, []byte{'\n'}) {
		rows++
		if rows > 64 || len(row) > 256 {
			return nil, fmt.Errorf("bcache: debug row limit")
		}
		if len(bytes.TrimSpace(row)) == 0 {
			continue
		}
		fields := bytes.Fields(row)
		key := strings.TrimSuffix(string(fields[0]), ":")
		switch key {
		case "rate", "dirty", "target", "proportional", "integral", "change", bcacheNext:
		default:
			continue
		}
		if len(fields) < 2 {
			return nil, fmt.Errorf("bcache: malformed debug row")
		}
		raw := bytes.TrimSuffix(fields[len(fields)-1], []byte("/sec"))
		if key == bcacheNext {
			raw = bytes.TrimSuffix(raw, []byte("ms"))
		}
		value, err := bcacheNumber(raw, key == "proportional" || key == "integral" || key == "change" || key == bcacheNext)
		if err != nil {
			return nil, err
		}
		if _, ok := values[key]; ok {
			return nil, fmt.Errorf("bcache: duplicate debug field")
		}
		values[key] = value
	}
	return values, nil
}
func (c *bcacheCollector) Update(target agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	sets, err := c.sets(in)
	if err != nil {
		return err
	}
	if _, err := c.ExpandDeep(target, in); err != nil {
		return err
	}
	var metrics []prometheus.Metric
	for _, uuid := range sets {
		devices, err := bcacheNames(in, bcacheList(uuid), bcacheDevice, agentless.MaxExpandedReads)
		if err != nil {
			return err
		}
		for _, dev := range append([]string{""}, devices...) {
			group := 0
			if strings.HasPrefix(dev, "bdev") {
				group = 1
			} else if dev != "" {
				group = 2
			}
			var debug map[string]float64
			if group == 1 {
				out, present, err := bcacheOutput(in, bcacheFile(uuid, dev, "writeback_rate_debug"))
				if err != nil {
					return err
				}
				if present {
					debug, err = bcacheDebug(out)
					if err != nil {
						return err
					}
				}
			}
			for i, s := range bcacheSpecs {
				if s.group != group {
					continue
				}
				var value float64
				if group == 1 && !strings.Contains(s.attr, "/") && s.attr != "dirty_data" {
					var ok bool
					value, ok = debug[s.attr]
					if !ok {
						continue
					}
				} else {
					out, present, err := bcacheOutput(in, bcacheFile(uuid, dev, s.attr))
					if err != nil {
						return err
					}
					if !present {
						continue
					}
					value, err = bcacheNumber(out, false)
					if err != nil {
						return fmt.Errorf("bcache: %s: %w", s.attr, err)
					}
				}
				if s.family == "cache_readaheads_total" && value == 0 {
					continue
				}
				labels := []string{uuid}
				if dev != "" {
					labels = append(labels, dev)
				}
				metrics = append(metrics, targetMetric(c.desc[i], s.kind, value*s.scale, labels...))
			}
		}
	}
	for _, m := range metrics {
		ch <- m
	}
	return nil
}
