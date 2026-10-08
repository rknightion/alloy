// Copyright 2017 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
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
	"strings"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs/xfs"
)

func init() {
	Register(Registration{Name: "xfs", OS: "linux", DefaultEnabled: true, Factory: newXfsCollector})
}

// All 39 families exported by the pinned upstream collector are ported.
// Other procfs stats (trans, log, push_ail, xstrat, attr, icluster, buf,
// *bt2, qm, xpc, debug) have no families in that collector. No proc fallback.
var xfsMetrics = [...]struct {
	name, help string
	value      func(*xfs.Stats) float64
}{
	{"extent_allocation_extents_allocated_total", "Number of extents allocated for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.ExtentAllocation.ExtentsAllocated) }},
	{"extent_allocation_blocks_allocated_total", "Number of blocks allocated for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.ExtentAllocation.BlocksAllocated) }},
	{"extent_allocation_extents_freed_total", "Number of extents freed for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.ExtentAllocation.ExtentsFreed) }},
	{"extent_allocation_blocks_freed_total", "Number of blocks freed for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.ExtentAllocation.BlocksFreed) }},
	{"allocation_btree_lookups_total", "Number of allocation B-tree lookups for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.AllocationBTree.Lookups) }},
	{"allocation_btree_compares_total", "Number of allocation B-tree compares for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.AllocationBTree.Compares) }},
	{"allocation_btree_records_inserted_total", "Number of allocation B-tree records inserted for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.AllocationBTree.RecordsInserted) }},
	{"allocation_btree_records_deleted_total", "Number of allocation B-tree records deleted for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.AllocationBTree.RecordsDeleted) }},
	{"block_mapping_reads_total", "Number of block map for read operations for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.BlockMapping.Reads) }},
	{"block_mapping_writes_total", "Number of block map for write operations for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.BlockMapping.Writes) }},
	{"block_mapping_unmaps_total", "Number of block unmaps (deletes) for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.BlockMapping.Unmaps) }},
	{"block_mapping_extent_list_insertions_total", "Number of extent list insertions for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.BlockMapping.ExtentListInsertions) }},
	{"block_mapping_extent_list_deletions_total", "Number of extent list deletions for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.BlockMapping.ExtentListDeletions) }},
	{"block_mapping_extent_list_lookups_total", "Number of extent list lookups for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.BlockMapping.ExtentListLookups) }},
	{"block_mapping_extent_list_compares_total", "Number of extent list compares for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.BlockMapping.ExtentListCompares) }},
	{"block_map_btree_lookups_total", "Number of block map B-tree lookups for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.BlockMapBTree.Lookups) }},
	{"block_map_btree_compares_total", "Number of block map B-tree compares for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.BlockMapBTree.Compares) }},
	{"block_map_btree_records_inserted_total", "Number of block map B-tree records inserted for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.BlockMapBTree.RecordsInserted) }},
	{"block_map_btree_records_deleted_total", "Number of block map B-tree records deleted for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.BlockMapBTree.RecordsDeleted) }},
	{"directory_operation_lookup_total", "Number of file name directory lookups which miss the operating systems directory name lookup cache.", func(s *xfs.Stats) float64 { return float64(s.DirectoryOperation.Lookups) }},
	{"directory_operation_create_total", "Number of times a new directory entry was created for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.DirectoryOperation.Creates) }},
	{"directory_operation_remove_total", "Number of times an existing directory entry was created for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.DirectoryOperation.Removes) }},
	{"directory_operation_getdents_total", "Number of times the directory getdents operation was performed for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.DirectoryOperation.Getdents) }},
	{"inode_operation_attempts_total", "Number of times the OS looked for an XFS inode in the inode cache.", func(s *xfs.Stats) float64 { return float64(s.InodeOperation.Attempts) }},
	{"inode_operation_found_total", "Number of times the OS looked for and found an XFS inode in the inode cache.", func(s *xfs.Stats) float64 { return float64(s.InodeOperation.Found) }},
	{"inode_operation_recycled_total", "Number of times the OS found an XFS inode in the cache, but could not use it as it was being recycled.", func(s *xfs.Stats) float64 { return float64(s.InodeOperation.Recycle) }},
	{"inode_operation_missed_total", "Number of times the OS looked for an XFS inode in the cache, but did not find it.", func(s *xfs.Stats) float64 { return float64(s.InodeOperation.Missed) }},
	{"inode_operation_duplicates_total", "Number of times the OS tried to add a missing XFS inode to the inode cache, but found it had already been added by another process.", func(s *xfs.Stats) float64 { return float64(s.InodeOperation.Duplicate) }},
	{"inode_operation_reclaims_total", "Number of times the OS reclaimed an XFS inode from the inode cache to free memory for another purpose.", func(s *xfs.Stats) float64 { return float64(s.InodeOperation.Reclaims) }},
	{"inode_operation_attribute_changes_total", "Number of times the OS explicitly changed the attributes of an XFS inode.", func(s *xfs.Stats) float64 { return float64(s.InodeOperation.AttributeChange) }},
	{"read_calls_total", "Number of read(2) system calls made to files in a filesystem.", func(s *xfs.Stats) float64 { return float64(s.ReadWrite.Read) }},
	{"write_calls_total", "Number of write(2) system calls made to files in a filesystem.", func(s *xfs.Stats) float64 { return float64(s.ReadWrite.Write) }},
	{"vnode_active_total", "Number of vnodes not on free lists for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.Vnode.Active) }},
	{"vnode_allocate_total", "Number of times vn_alloc called for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.Vnode.Allocate) }},
	{"vnode_get_total", "Number of times vn_get called for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.Vnode.Get) }},
	{"vnode_hold_total", "Number of times vn_hold called for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.Vnode.Hold) }},
	{"vnode_release_total", "Number of times vn_rele called for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.Vnode.Release) }},
	{"vnode_reclaim_total", "Number of times vn_reclaim called for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.Vnode.Reclaim) }},
	{"vnode_remove_total", "Number of times vn_remove called for a filesystem.", func(s *xfs.Stats) float64 { return float64(s.Vnode.Remove) }},
}

type xfsCollector struct {
	desc [len(xfsMetrics)]*prometheus.Desc
}

var _ agentless.Expander = (*xfsCollector)(nil)

func newXfsCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	c := &xfsCollector{}
	for i, spec := range xfsMetrics {
		c.desc[i] = prometheus.NewDesc(agentless.Namespace+"_xfs_"+spec.name, spec.help, []string{"device"}, nil)
	}
	return c, nil
}
func (*xfsCollector) Name() string { return "xfs" }
func (*xfsCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.CommandRead("ls", "-1", "/sys/fs/xfs")}
}
func xfsRead(device string) agentless.Read {
	return agentless.FileRead("/sys/fs/xfs/" + device + "/stats/stats")
}
func xfsOutput(in agentless.Input, read agentless.Read) ([]byte, bool, error) {
	if err := read.Validate(); err != nil {
		return nil, false, err
	}
	result := in[read.ID]
	if result.NotExist && !result.TimedOut && !result.Truncated {
		return nil, false, nil
	}
	out, err := in.Output(read)
	return out, err == nil, err
}
func (c *xfsCollector) devices(in agentless.Input) ([]string, error) {
	out, _, err := xfsOutput(in, c.Reads()[0])
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	if out[len(out)-1] != '\n' {
		return nil, fmt.Errorf("xfs: unterminated listing")
	}
	var devices []string
	rows := 0
	for row := range bytes.SplitSeq(out[:len(out)-1], []byte{'\n'}) {
		rows++
		if rows > agentless.MaxExpandedReads || len(row) > 4096 || len(row) == 0 {
			return nil, fmt.Errorf("xfs: listing limit exceeded")
		}
		device := string(row)
		if strings.Contains(device, "/") || device == "." || xfsRead(device).Validate() != nil {
			continue
		}
		for _, previous := range devices {
			if previous == device {
				return nil, fmt.Errorf("xfs: duplicate device")
			}
		}
		// One read per device, 39 series each: bound both the expansion and
		// retained metrics to the existing 1024-read / 20000-series limits.
		if len(devices) >= agentless.MaxExpandedReads || (len(devices)+1)*len(xfsMetrics) > 20000 {
			return nil, fmt.Errorf("xfs: expansion limit exceeded")
		}
		devices = append(devices, device)
	}
	return devices, nil
}
func (c *xfsCollector) Expand(_ agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	devices, err := c.devices(in)
	if err != nil {
		return nil, err
	}
	reads := make([]agentless.Read, 0, len(devices))
	for _, device := range devices {
		read := xfsRead(device)
		if err := read.Validate(); err != nil {
			return nil, err
		}
		reads = append(reads, read)
	}
	return reads, nil
}

// Bound bytes, rows and tokens before the upstream parser allocates strings
// or integer slices. Unknown future rows remain parseable within these bounds.
func xfsStats(out []byte) (*xfs.Stats, error) {
	if len(out) > 64*1024 {
		return nil, fmt.Errorf("xfs: stats byte limit exceeded")
	}
	rows := 0
	for row := range bytes.SplitSeq(out, []byte{'\n'}) {
		rows++
		if rows > 128 || len(row) > 1024 {
			return nil, fmt.Errorf("xfs: stats row limit exceeded")
		}
		fields := 0
		for token := range bytes.FieldsSeq(row) {
			fields++
			if fields > 32 || len(token) > 32 {
				return nil, fmt.Errorf("xfs: stats token limit exceeded")
			}
		}
	}
	return xfs.ParseStats(bytes.NewReader(out))
}
func (c *xfsCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	devices, err := c.devices(in)
	if err != nil {
		return err
	}
	var metrics []prometheus.Metric
	for _, device := range devices {
		out, present, err := xfsOutput(in, xfsRead(device))
		if err != nil {
			return err
		}
		if !present {
			continue
		}
		stats, err := xfsStats(out)
		if err != nil {
			return fmt.Errorf("xfs: invalid stats: %w", err)
		}
		for i, spec := range xfsMetrics {
			metrics = append(metrics, targetMetric(c.desc[i], prometheus.CounterValue, spec.value(stats), device))
		}
	}
	for _, metric := range metrics {
		ch <- metric
	}
	return nil
}
