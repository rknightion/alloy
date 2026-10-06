package collectors

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	Register(Registration{Name: "ipvs", OS: "linux", DefaultEnabled: false, Factory: newIPVSCollector})
}

// Five global counters plus three series per backend fit the frozen 20000
// series cap. Count input backends before tokenization, including duplicates.
const maxIPVSBackends = (20000 - 5) / 3

var ipvsFamilies = [...]struct{ name, help string }{
	{"connections_total", "The total number of connections made."},
	{"incoming_packets_total", "The total number of incoming packets."},
	{"outgoing_packets_total", "The total number of outgoing packets."},
	{"incoming_bytes_total", "The total amount of incoming data."},
	{"outgoing_bytes_total", "The total amount of outgoing data."},
	{"backend_connections_active", "The current active connections by local and remote address."},
	{"backend_connections_inactive", "The current inactive connections by local and remote address."},
	{"backend_weight", "The current backend weight by local and remote address."},
}

type ipvsCollector struct{ descs [8]*prometheus.Desc }

func newIPVSCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	c := &ipvsCollector{}
	for i, f := range ipvsFamilies {
		var labels []string
		if i >= 5 {
			labels = []string{"local_address", "local_port", "remote_address", "remote_port", "proto", "local_mark"}
		}
		c.descs[i] = prometheus.NewDesc(agentless.Namespace+"_ipvs_"+f.name, f.help, labels, nil)
	}
	return c, nil
}
func (*ipvsCollector) Name() string { return "ipvs" }
func (*ipvsCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/net/ip_vs_stats"), agentless.FileRead("/proc/net/ip_vs")}
}
func (c *ipvsCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	var stats [5]uint64
	var backends []ipvsBackend
	var present bool
	for i, read := range c.Reads() {
		result := in[read.ID]
		if result.NotExist && !result.TimedOut && !result.Truncated {
			continue
		}
		output, err := in.Output(read)
		if err != nil {
			return err
		}
		if i == 0 {
			stats, err = parseIPVSStats(output)
			present = true
		} else {
			backends, err = parseIPVSBackends(output)
		}
		if err != nil {
			return err
		}
	}
	// Validate both optional snapshots before publishing any metrics.
	if present {
		for i, value := range stats {
			ch <- targetMetric(c.descs[i], prometheus.CounterValue, float64(value))
		}
	}
	for _, backend := range backends {
		for i, value := range backend.values {
			ch <- targetMetric(c.descs[5+i], prometheus.GaugeValue, float64(value), backend.labels[:]...)
		}
	}
	return nil
}

func parseIPVSStats(output []byte) ([5]uint64, error) {
	var stats [5]uint64
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	for i := range 3 {
		if !scanner.Scan() {
			return stats, errors.New("ipvs: short stats file")
		}
		if i != 2 {
			continue
		}
		n := 0
		for field := range bytes.FieldsSeq(scanner.Bytes()) {
			if n == len(stats) || len(field) > 16 {
				return stats, errors.New("ipvs: invalid stats fields")
			}
			value, err := strconv.ParseUint(string(field), 16, 64)
			if err != nil {
				return stats, fmt.Errorf("ipvs: stats: %w", err)
			}
			stats[n] = value
			n++
		}
		if n != len(stats) {
			return stats, errors.New("ipvs: missing stats fields")
		}
	}
	// procfs reads only the cumulative row; rate rows are not exported.
	if !scanner.Scan() {
		return stats, errors.New("ipvs: short stats file")
	}
	return stats, nil
}

type ipvsBackend struct {
	labels [6]string
	values [3]uint64
}

func parseIPVSBackends(output []byte) ([]ipvsBackend, error) {
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	// Fixed retention and in-place sorting avoid randomized map-growth
	// allocations when comparing a capped snapshot with hostile excess tails.
	sums := make([]ipvsBackend, 0, maxIPVSBackends)
	var local [6]string
	rows, backends, services := 0, 0, 0
	for scanner.Scan() {
		rows++
		// Also bound blank, header, and service rows, not just retained backends.
		if rows > 3+2*maxIPVSBackends {
			return nil, errors.New("ipvs: row limit exceeded")
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if bytes.HasPrefix(line, []byte("->")) && backends == maxIPVSBackends {
			return nil, errors.New("ipvs: backend limit exceeded")
		}
		var fields [8]string
		n := 0
		for field := range bytes.FieldsSeq(line) {
			if n == len(fields) || len(field) > 4096 {
				return nil, errors.New("ipvs: invalid fields")
			}
			fields[n] = string(field)
			n++
		}
		if n == 0 {
			continue
		}
		switch fields[0] {
		case "IP", "Prot":
			if rows > 2 {
				return nil, errors.New("ipvs: misplaced header")
			}
		case "TCP", "UDP", "FWM":
			if n < 3 {
				return nil, errors.New("ipvs: short service")
			}
			services++
			if services > maxIPVSBackends {
				return nil, errors.New("ipvs: service limit exceeded")
			}
			local = [6]string{"", "0", "", "", fields[0], ""}
			if fields[0] == "FWM" {
				local[5] = fields[1]
			} else {
				address, port, err := parseIPVSEndpoint(fields[1])
				if err != nil {
					return nil, err
				}
				local[0], local[1] = address, port
			}
		case "->":
			if n == 6 && fields[1] == "RemoteAddress:Port" && rows == 3 {
				continue
			}
			if n != 6 || local[4] == "" {
				return nil, errors.New("ipvs: malformed backend")
			}
			backends++
			address, port, err := parseIPVSEndpoint(fields[1])
			if err != nil {
				return nil, err
			}
			labels := local
			labels[2], labels[3] = address, port
			var values [3]uint64
			for i, col := range [...]int{4, 5, 3} {
				if len(fields[col]) > 20 {
					return nil, errors.New("ipvs: oversized value")
				}
				value, err := strconv.ParseUint(fields[col], 10, 64)
				if err != nil {
					return nil, fmt.Errorf("ipvs: backend: %w", err)
				}
				// Match upstream uint64 aggregation semantics.
				values[i] += value
			}
			sums = append(sums, ipvsBackend{labels: labels, values: values})
		default:
			return nil, errors.New("ipvs: unknown row")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("ipvs: scan: %w", err)
	}
	if rows < 3 {
		return nil, errors.New("ipvs: short backend file")
	}
	slices.SortFunc(sums, func(a, b ipvsBackend) int {
		for i := range a.labels {
			if cmp := strings.Compare(a.labels[i], b.labels[i]); cmp != 0 {
				return cmp
			}
		}
		return 0
	})
	merged := sums[:0]
	for _, row := range sums {
		if len(merged) > 0 && merged[len(merged)-1].labels == row.labels {
			for i, value := range row.values {
				merged[len(merged)-1].values[i] += value
			}
		} else {
			merged = append(merged, row)
		}
	}
	return merged, nil
}

func parseIPVSEndpoint(raw string) (string, string, error) {
	var address netip.Addr
	switch {
	case len(raw) == 13 && raw[8] == ':':
		value, err := strconv.ParseUint(raw[:8], 16, 32)
		if err != nil {
			return "", "", err
		}
		address = netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
	case len(raw) == 46 && raw[0] == '[' && raw[40:42] == "]:":
		var err error
		address, err = netip.ParseAddr(raw[1:40])
		if err != nil || !address.Is6() {
			return "", "", errors.New("ipvs: invalid IPv6 address")
		}
	default:
		return "", "", errors.New("ipvs: invalid endpoint")
	}
	port, err := strconv.ParseUint(raw[len(raw)-4:], 16, 16)
	if err != nil || strings.Contains(raw, "%") {
		return "", "", errors.New("ipvs: invalid port")
	}
	// procfs/node_exporter renders mapped IPv6 with net.IP.String as IPv4.
	return address.Unmap().String(), strconv.FormatUint(port, 10), nil
}
