package collectors

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"reflect"
	"strconv"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs/nfs"
)

func init() {
	Register(Registration{Name: "nfs", OS: "linux", DefaultEnabled: false, Factory: newNFSCollector})
}

type nfsCollector struct{ descs [6]*prometheus.Desc }

func newNFSCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	c := &nfsCollector{}
	for i, spec := range [...]struct {
		name, help string
		labels     []string
	}{
		{"packets_total", "Total NFSd network packets (sent+received) by protocol type.", []string{"protocol"}},
		{"connections_total", "Total number of NFSd TCP connections.", nil},
		{"rpcs_total", "Total number of RPCs performed.", nil},
		{"rpc_retransmissions_total", "Number of RPC transmissions performed.", nil},
		{"rpc_authentication_refreshes_total", "Number of RPC authentication refreshes performed.", nil},
		{"requests_total", "Number of NFS procedures invoked.", []string{"proto", "method"}},
	} {
		c.descs[i] = prometheus.NewDesc(agentless.Namespace+"_nfs_"+spec.name, spec.help, spec.labels, nil)
	}
	return c, nil
}

func (*nfsCollector) Name() string { return "nfs" }
func (*nfsCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/net/rpc/nfs")}
}

func (c *nfsCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	read := c.Reads()[0]
	result := in[read.ID]
	if result.NotExist && !result.TimedOut && !result.Truncated {
		return nil
	}
	output, err := in.Output(read)
	if err != nil {
		return err
	}
	stats, err := parseNFSStats(output)
	if err != nil {
		return err
	}
	ch <- targetMetric(c.descs[0], prometheus.CounterValue, float64(stats.Network.UDPCount), "udp")
	ch <- targetMetric(c.descs[0], prometheus.CounterValue, float64(stats.Network.TCPCount), "tcp")
	for i, value := range [...]uint64{stats.Network.TCPConnect, stats.ClientRPC.RPCCount, stats.ClientRPC.Retransmissions, stats.ClientRPC.AuthRefreshes} {
		ch <- targetMetric(c.descs[i+1], prometheus.CounterValue, float64(value))
	}
	for i, row := range [...]any{stats.V2Stats, stats.V3Stats, stats.ClientV4Stats} {
		v := reflect.ValueOf(row)
		for field := 0; field < v.NumField(); field++ {
			ch <- targetMetric(c.descs[5], prometheus.CounterValue, float64(v.Field(field).Uint()), strconv.Itoa(i+2), v.Type().Field(field).Name)
		}
	}
	return nil
}

// Validate before procfs allocates token/value slices. Only five unique rows,
// at most 500 numeric fields each, and 20-byte uint64 tokens are admitted.
// Emission is fixed at six families / 105 series with source-independent labels,
// below the frozen 500-family, 20000-series and 4096-label-byte caps. Extra
// procedure counters are validated but ignored, as in procfs; old v4 rows pad.
func parseNFSStats(output []byte) (*nfs.ClientRPCStats, error) {
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 16*1024), 16*1024)
	var seen [5]bool
	rows := 0
	for scanner.Scan() {
		rows++
		if rows > len(seen) {
			return nil, fmt.Errorf("nfs: row limit exceeded")
		}
		index, count := -1, 0
		var declared uint64
		for token := range bytes.FieldsSeq(scanner.Bytes()) {
			if count == 0 {
				switch string(token) {
				case "net":
					index = 0
				case "rpc":
					index = 1
				case "proc2":
					index = 2
				case "proc3":
					index = 3
				case "proc4":
					index = 4
				default:
					return nil, fmt.Errorf("nfs: unknown row")
				}
				if seen[index] {
					return nil, fmt.Errorf("nfs: duplicate row")
				}
				seen[index] = true
			} else {
				if count > 500 || len(token) > 20 {
					return nil, fmt.Errorf("nfs: field limit exceeded")
				}
				value, err := strconv.ParseUint(string(token), 10, 64)
				if err != nil {
					return nil, fmt.Errorf("nfs: invalid counter")
				}
				if count == 1 {
					declared = value
				}
			}
			count++
		}
		if index < 0 || count < 2 {
			return nil, fmt.Errorf("nfs: empty row")
		}
		switch index {
		case 0:
			if count != 5 {
				return nil, fmt.Errorf("nfs: invalid net width")
			}
		case 1:
			if count != 4 {
				return nil, fmt.Errorf("nfs: invalid rpc width")
			}
		default:
			minimum := uint64(0)
			switch index {
			case 2:
				minimum = 18
			case 3:
				minimum = 22
			}
			if declared != uint64(count-2) || declared < minimum {
				return nil, fmt.Errorf("nfs: invalid procedure width")
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("nfs: scan: %w", err)
	}
	if rows == 0 {
		return nil, fmt.Errorf("nfs: empty file")
	}
	stats, err := nfs.ParseClientRPCStats(bytes.NewReader(output))
	if err != nil {
		return nil, err
	}
	// The pinned exporter uses procfs v0.16.1, whose slots 45/46 are
	// LayoutGet/GetDeviceInfo. Preserve that row contract rather than the
	// reversed mapping in this repository's newer procfs parser.
	stats.ClientV4Stats.LayoutGet, stats.ClientV4Stats.GetDeviceInfo = stats.ClientV4Stats.GetDeviceInfo, stats.ClientV4Stats.LayoutGet
	return stats, nil
}
