// Copyright 2018 The Prometheus Authors
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

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs/nfs"
)

func init() {
	Register(Registration{Name: "nfsd", OS: "linux", DefaultEnabled: false, Factory: newNFSdCollector})
}

type nfsdCollector struct{ requestsDesc *prometheus.Desc }

func newNFSdCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &nfsdCollector{requestsDesc: prometheus.NewDesc(agentless.Namespace+"_nfsd_requests_total", "Total number NFSd Requests by method and protocol.", []string{"proto", "method"}, nil)}, nil
}
func (c *nfsdCollector) Name() string { return "nfsd" }
func (c *nfsdCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/net/rpc/nfsd")}
}

func (c *nfsdCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	read := c.Reads()[0]
	if result, ok := in[read.ID]; ok && result.NotExist && !result.Truncated && !result.TimedOut {
		return nil
	}
	output, err := in.Output(read)
	if err != nil {
		return fmt.Errorf("nfsd: %w", err)
	}
	stats, err := parseNFSd(output)
	if err != nil {
		return err
	}
	c.updateNFSdReplyCacheStats(ch, &stats.ReplyCache)
	c.updateNFSdFileHandlesStats(ch, &stats.FileHandles)
	c.updateNFSdInputOutputStats(ch, &stats.InputOutput)
	c.updateNFSdThreadsStats(ch, &stats.Threads)
	c.updateNFSdReadAheadCacheStats(ch, &stats.ReadAheadCache)
	c.updateNFSdNetworkStats(ch, &stats.Network)
	c.updateNFSdServerRPCStats(ch, &stats.ServerRPC)
	c.updateNFSdRequestsv2Stats(ch, &stats.V2Stats)
	c.updateNFSdRequestsv3Stats(ch, &stats.V3Stats)
	c.updateNFSdRequestsv4Stats(ch, &stats.V4Ops)

	return nil
}

// Validate bounds before procfs tokenizes or retains anything. Only twelve
// distinct kernel records, 128 fields per record and 4096 bytes per line can
// reach procfs. Output is fixed at 14 families and 87 series, with fixed labels
// well below the frozen 20000-series, 500-family and 4096-label-byte caps.
// procfs preserves older kernels' missing records as zero-valued statistics.
func parseNFSd(output []byte) (*nfs.ServerRPCStats, error) {
	const maxLine = 4096
	keys := [...]string{"rc", "fh", "io", "th", "ra", "net", "rpc", "proc2", "proc3", "proc4", "proc4ops", "wdeleg_getattr"}
	var seen [len(keys)]bool
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, maxLine), maxLine)
	lines := 0
	for scanner.Scan() {
		lines++
		if lines > len(keys) {
			return nil, fmt.Errorf("nfsd: too many records")
		}
		fields := 0
		key := ""
		for field := range bytes.FieldsSeq(scanner.Bytes()) {
			fields++
			if fields == 1 {
				key = string(field)
			}
			if fields > 128 {
				return nil, fmt.Errorf("nfsd: too many fields")
			}
		}
		if fields < 2 || (key == "th" && fields < 3) {
			return nil, fmt.Errorf("nfsd: incomplete record")
		}
		index := -1
		for i, candidate := range keys {
			if key == candidate {
				index = i
				break
			}
		}
		if index < 0 {
			return nil, fmt.Errorf("nfsd: unknown record")
		}
		if seen[index] {
			return nil, fmt.Errorf("nfsd: duplicate record")
		}
		seen[index] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("nfsd: scan: %w", err)
	}
	if lines == 0 {
		return nil, fmt.Errorf("nfsd: empty input")
	}
	stats, err := nfs.ParseServerRPCStats(bytes.NewReader(output))
	if err != nil {
		return nil, fmt.Errorf("nfsd: %w", err)
	}
	return stats, nil
}

// updateNFSdReplyCacheStats collects statistics for the reply cache.
func (c *nfsdCollector) updateNFSdReplyCacheStats(ch chan<- prometheus.Metric, s *nfs.ReplyCache) {
	ch <- targetMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName(agentless.Namespace, "nfsd", "reply_cache_hits_total"),
			"Total number of NFSd Reply Cache hits (client lost server response).",
			nil,
			nil,
		),
		prometheus.CounterValue,
		float64(s.Hits))
	ch <- targetMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName(agentless.Namespace, "nfsd", "reply_cache_misses_total"),
			"Total number of NFSd Reply Cache an operation that requires caching (idempotent).",
			nil,
			nil,
		),
		prometheus.CounterValue,
		float64(s.Misses))
	ch <- targetMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName(agentless.Namespace, "nfsd", "reply_cache_nocache_total"),
			"Total number of NFSd Reply Cache non-idempotent operations (rename/delete/…).",
			nil,
			nil,
		),
		prometheus.CounterValue,
		float64(s.NoCache))
}

// updateNFSdFileHandlesStats collects statistics for the file handles.
func (c *nfsdCollector) updateNFSdFileHandlesStats(ch chan<- prometheus.Metric, s *nfs.FileHandles) {
	ch <- targetMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName(agentless.Namespace, "nfsd", "file_handles_stale_total"),
			"Total number of NFSd stale file handles",
			nil,
			nil,
		),
		prometheus.CounterValue,
		float64(s.Stale))
	// NOTE: Other FileHandles entries are unused in the kernel.
}

// updateNFSdInputOutputStats collects statistics for the bytes in/out.
func (c *nfsdCollector) updateNFSdInputOutputStats(ch chan<- prometheus.Metric, s *nfs.InputOutput) {
	ch <- targetMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName(agentless.Namespace, "nfsd", "disk_bytes_read_total"),
			"Total NFSd bytes read.",
			nil,
			nil,
		),
		prometheus.CounterValue,
		float64(s.Read))
	ch <- targetMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName(agentless.Namespace, "nfsd", "disk_bytes_written_total"),
			"Total NFSd bytes written.",
			nil,
			nil,
		),
		prometheus.CounterValue,
		float64(s.Write))
}

// updateNFSdThreadsStats collects statistics for kernel server threads.
func (c *nfsdCollector) updateNFSdThreadsStats(ch chan<- prometheus.Metric, s *nfs.Threads) {
	ch <- targetMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName(agentless.Namespace, "nfsd", "server_threads"),
			"Total number of NFSd kernel threads that are running.",
			nil,
			nil,
		),
		prometheus.GaugeValue,
		float64(s.Threads))
}

// updateNFSdReadAheadCacheStats collects statistics for the read ahead cache.
func (c *nfsdCollector) updateNFSdReadAheadCacheStats(ch chan<- prometheus.Metric, s *nfs.ReadAheadCache) {
	ch <- targetMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName(agentless.Namespace, "nfsd", "read_ahead_cache_size_blocks"),
			"How large the read ahead cache is in blocks.",
			nil,
			nil,
		),
		prometheus.GaugeValue,
		float64(s.CacheSize))
	ch <- targetMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName(agentless.Namespace, "nfsd", "read_ahead_cache_not_found_total"),
			"Total number of NFSd read ahead cache not found.",
			nil,
			nil,
		),
		prometheus.CounterValue,
		float64(s.NotFound))
}

// updateNFSdNetworkStats collects statistics for network packets/connections.
func (c *nfsdCollector) updateNFSdNetworkStats(ch chan<- prometheus.Metric, s *nfs.Network) {
	packetDesc := prometheus.NewDesc(
		prometheus.BuildFQName(agentless.Namespace, "nfsd", "packets_total"),
		"Total NFSd network packets (sent+received) by protocol type.",
		[]string{"proto"},
		nil,
	)
	ch <- targetMetric(
		packetDesc,
		prometheus.CounterValue,
		float64(s.UDPCount), "udp")
	ch <- targetMetric(
		packetDesc,
		prometheus.CounterValue,
		float64(s.TCPCount), "tcp")
	ch <- targetMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName(agentless.Namespace, "nfsd", "connections_total"),
			"Total number of NFSd TCP connections.",
			nil,
			nil,
		),
		prometheus.CounterValue,
		float64(s.TCPConnect))
}

// updateNFSdServerRPCStats collects statistics for kernel server RPCs.
func (c *nfsdCollector) updateNFSdServerRPCStats(ch chan<- prometheus.Metric, s *nfs.ServerRPC) {
	badRPCDesc := prometheus.NewDesc(
		prometheus.BuildFQName(agentless.Namespace, "nfsd", "rpc_errors_total"),
		"Total number of NFSd RPC errors by error type.",
		[]string{"error"},
		nil,
	)
	ch <- targetMetric(
		badRPCDesc,
		prometheus.CounterValue,
		float64(s.BadFmt), "fmt")
	ch <- targetMetric(
		badRPCDesc,
		prometheus.CounterValue,
		float64(s.BadAuth), "auth")
	ch <- targetMetric(
		badRPCDesc,
		prometheus.CounterValue,
		float64(s.BadcInt), "cInt")
	ch <- targetMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName(agentless.Namespace, "nfsd", "server_rpcs_total"),
			"Total number of NFSd RPCs.",
			nil,
			nil,
		),
		prometheus.CounterValue,
		float64(s.RPCCount))
}

// updateNFSdRequestsv2Stats collects statistics for NFSv2 requests.
func (c *nfsdCollector) updateNFSdRequestsv2Stats(ch chan<- prometheus.Metric, s *nfs.V2Stats) {
	const proto = "2"
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.GetAttr), proto, "GetAttr")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.SetAttr), proto, "SetAttr")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Root), proto, "Root")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Lookup), proto, "Lookup")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.ReadLink), proto, "ReadLink")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Read), proto, "Read")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.WrCache), proto, "WrCache")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Write), proto, "Write")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Create), proto, "Create")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Remove), proto, "Remove")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Rename), proto, "Rename")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Link), proto, "Link")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.SymLink), proto, "SymLink")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.MkDir), proto, "MkDir")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.RmDir), proto, "RmDir")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.ReadDir), proto, "ReadDir")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.FsStat), proto, "FsStat")
}

// updateNFSdRequestsv3Stats collects statistics for NFSv3 requests.
func (c *nfsdCollector) updateNFSdRequestsv3Stats(ch chan<- prometheus.Metric, s *nfs.V3Stats) {
	const proto = "3"
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.GetAttr), proto, "GetAttr")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.SetAttr), proto, "SetAttr")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Lookup), proto, "Lookup")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Access), proto, "Access")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.ReadLink), proto, "ReadLink")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Read), proto, "Read")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Write), proto, "Write")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Create), proto, "Create")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.MkDir), proto, "MkDir")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.SymLink), proto, "SymLink")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.MkNod), proto, "MkNod")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Remove), proto, "Remove")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.RmDir), proto, "RmDir")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Rename), proto, "Rename")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Link), proto, "Link")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.ReadDir), proto, "ReadDir")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.ReadDirPlus), proto, "ReadDirPlus")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.FsStat), proto, "FsStat")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.FsInfo), proto, "FsInfo")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.PathConf), proto, "PathConf")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Commit), proto, "Commit")
}

// updateNFSdRequestsv4Stats collects statistics for NFSv4 requests.
func (c *nfsdCollector) updateNFSdRequestsv4Stats(ch chan<- prometheus.Metric, s *nfs.V4Ops) {
	const proto = "4"
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Access), proto, "Access")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Close), proto, "Close")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Commit), proto, "Commit")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Create), proto, "Create")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.DelegPurge), proto, "DelegPurge")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.DelegReturn), proto, "DelegReturn")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.GetAttr), proto, "GetAttr")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.GetFH), proto, "GetFH")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Link), proto, "Link")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Lock), proto, "Lock")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Lockt), proto, "Lockt")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Locku), proto, "Locku")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Lookup), proto, "Lookup")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.LookupRoot), proto, "LookupRoot")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Nverify), proto, "Nverify")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Open), proto, "Open")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.OpenAttr), proto, "OpenAttr")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.OpenConfirm), proto, "OpenConfirm")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.OpenDgrd), proto, "OpenDgrd")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.PutFH), proto, "PutFH")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Read), proto, "Read")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.ReadDir), proto, "ReadDir")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.ReadLink), proto, "ReadLink")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Remove), proto, "Remove")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Rename), proto, "Rename")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Renew), proto, "Renew")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.RestoreFH), proto, "RestoreFH")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.SaveFH), proto, "SaveFH")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.SecInfo), proto, "SecInfo")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.SetAttr), proto, "SetAttr")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Verify), proto, "Verify")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.Write), proto, "Write")
	ch <- targetMetric(c.requestsDesc, prometheus.CounterValue,
		float64(s.RelLockOwner), proto, "RelLockOwner")
}
