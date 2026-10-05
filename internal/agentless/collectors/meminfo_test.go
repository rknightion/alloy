package collectors

import (
	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/prometheus/client_golang/prometheus"
	"strings"
	"testing"
)

func TestMeminfoConformance(t *testing.T) {
	conformance.Check(t, conformance.Case{Collector: &meminfoCollector{}, Families: []string{
		"node_memory_Active_anon_bytes",
		"node_memory_Active_bytes",
		"node_memory_Active_file_bytes",
		"node_memory_AnonHugePages_bytes",
		"node_memory_AnonPages_bytes",
		"node_memory_Bounce_bytes",
		"node_memory_Buffers_bytes",
		"node_memory_Cached_bytes",
		"node_memory_CommitLimit_bytes",
		"node_memory_Committed_AS_bytes",
		"node_memory_DirectMap2M_bytes",
		"node_memory_DirectMap4k_bytes",
		"node_memory_Dirty_bytes",
		"node_memory_HardwareCorrupted_bytes",
		"node_memory_HugePages_Free",
		"node_memory_HugePages_Rsvd",
		"node_memory_HugePages_Surp",
		"node_memory_HugePages_Total",
		"node_memory_Hugepagesize_bytes",
		"node_memory_Inactive_anon_bytes",
		"node_memory_Inactive_bytes",
		"node_memory_Inactive_file_bytes",
		"node_memory_KernelStack_bytes",
		"node_memory_Mapped_bytes",
		"node_memory_MemFree_bytes",
		"node_memory_MemTotal_bytes",
		"node_memory_Mlocked_bytes",
		"node_memory_NFS_Unstable_bytes",
		"node_memory_PageTables_bytes",
		"node_memory_SReclaimable_bytes",
		"node_memory_SUnreclaim_bytes",
		"node_memory_Shmem_bytes",
		"node_memory_Slab_bytes",
		"node_memory_SwapCached_bytes",
		"node_memory_SwapFree_bytes",
		"node_memory_SwapTotal_bytes",
		"node_memory_Unevictable_bytes",
		"node_memory_VmallocChunk_bytes",
		"node_memory_VmallocTotal_bytes",
		"node_memory_VmallocUsed_bytes",
		"node_memory_WritebackTmp_bytes",
		"node_memory_Writeback_bytes",
	}})
}

func TestMeminfoRejectsMalformed(t *testing.T) {
	for _, output := range []string{"", "garbage", "MemTotal: nope kB", "MemTotal: -1 kB", "MemTotal: 1 MB", "MemTotal 1 kB", "MemTotal: 1 kB extra", "MemTotal: 1 kB\nMemTotal: 2 kB", "Bad-name: 1", strings.Repeat("x", 70000)} {
		t.Run(output[:min(len(output), 40)], func(t *testing.T) {
			c := &meminfoCollector{}
			read := c.Reads()[0]
			ch := make(chan prometheus.Metric, 100)
			err := c.Update(agentless.Target{}, agentless.Input{read.ID: {Read: read, Output: []byte("MemFree: 3 kB\n" + output)}}, ch)
			// Empty input is checked separately; an empty trailing line is valid.
			if output == "" {
				err = c.Update(agentless.Target{}, agentless.Input{read.ID: {Read: read}}, ch)
			}
			if err == nil {
				t.Fatal("accepted malformed output")
			}
			if len(ch) != 0 && output != "" {
				t.Fatal("emitted partial metrics")
			}
		})
	}
}

func TestMeminfoReadFailures(t *testing.T) {
	c := &meminfoCollector{}
	read := c.Reads()[0]
	for _, in := range []agentless.Input{nil, {read.ID: {ExitStatus: 1}}, {read.ID: {Truncated: true}}, {read.ID: {TimedOut: true}}} {
		if err := c.Update(agentless.Target{}, in, make(chan prometheus.Metric, 100)); err == nil {
			t.Fatal("accepted failed read")
		}
	}
}
