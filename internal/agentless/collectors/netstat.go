package collectors

import (
	"bufio"
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
	Register(Registration{Name: "netstat", OS: "linux", DefaultEnabled: true, Factory: newNetstatCollector})
}

// Match node_exporter's default field selection. No configurable reads or filters.
func netstatFieldSelected(key string) bool {
	// The former regexp's wildcard matches every byte sequence except a newline.
	if strings.IndexByte(key, '\n') >= 0 {
		return false
	}
	if strings.HasSuffix(key, "_InErrors") || strings.HasSuffix(key, "_InErrs") {
		return true
	}
	protocol, name, ok := strings.Cut(key, "_")
	if !ok {
		return false
	}
	switch protocol {
	case "Ip":
		return name == "Forwarding"
	case "Ip6", "IpExt":
		return name == "InOctets" || name == "OutOctets"
	case "Icmp", "Icmp6":
		return name == "InMsgs" || name == "OutMsgs"
	case "TcpExt":
		return strings.HasPrefix(name, "Listen") || strings.HasPrefix(name, "Syncookies") || name == "TCPSynRetrans" || name == "TCPTimeouts"
	case "Tcp":
		switch name {
		case "ActiveOpens", "InSegs", "OutSegs", "OutRsts", "PassiveOpens", "RetransSegs", "CurrEstab":
			return true
		}
	case "Udp", "Udp6":
		switch name {
		case "InDatagrams", "OutDatagrams", "NoPorts", "RcvbufErrors", "SndbufErrors":
			return true
		}
	}
	return false
}

// Bound all retained fields, including filtered fields, before metric emission.
// The central Scraper cannot bound a collector's pre-send parsing state.
const maxNetstatFields = 500

const netstatSNMP6Path = "/proc/net/snmp6"

type netstatCollector struct{}

func newNetstatCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &netstatCollector{}, nil
}

func (c *netstatCollector) Name() string { return "netstat" }

func (c *netstatCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/net/snmp"), agentless.FileRead(netstatSNMP6Path), agentless.FileRead("/proc/net/netstat")}
}

func (c *netstatCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	seen := make(map[string]bool)
	var metrics []prometheus.Metric
	// Reserve before retaining a name, even when it would be filtered out.
	reserve := func(protocol, name string) (string, error) {
		if len(seen) == maxNetstatFields {
			return "", fmt.Errorf("netstat: field limit exceeded (%d)", maxNetstatFields)
		}
		if protocol == "" || name == "" || !validMeminfoKey(protocol) || !validMeminfoKey(name) {
			return "", fmt.Errorf("netstat: invalid field name")
		}
		key := protocol + "_" + name
		if seen[key] {
			return "", fmt.Errorf("netstat: duplicate field %s", key)
		}
		seen[key] = true
		return key, nil
	}
	add := func(key, text string) error {
		value, err := strconv.ParseFloat(text, 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
			return fmt.Errorf("netstat: invalid value for %s", key)
		}
		if netstatFieldSelected(key) {
			protocol, name, _ := strings.Cut(key, "_")
			desc := prometheus.NewDesc(agentless.Namespace+"_netstat_"+key, "Statistic "+protocol+name+".", nil, nil)
			metric, err := prometheus.NewConstMetric(desc, prometheus.UntypedValue, value)
			if err != nil {
				return err
			}
			metrics = append(metrics, metric)
		}
		return nil
	}
	for _, read := range c.Reads() {
		result, ok := in[read.ID]
		if ok && result.NotExist && !result.TimedOut && !result.Truncated {
			continue
		}
		output, err := in.Output(read)
		if err != nil {
			return err
		}
		scanner := bufio.NewScanner(bytes.NewReader(output))
		rows := 0
		for scanner.Scan() {
			rows++
			// FieldsSeq avoids allocating a slice proportional to a hostile line.
			if read.Path == netstatSNMP6Path {
				var key string
				count := 0
				for field := range strings.FieldsSeq(scanner.Text()) {
					count++
					switch count {
					case 1:
						i := strings.IndexByte(field, '6')
						if i < 0 {
							return fmt.Errorf("netstat: malformed snmp6 field")
						}
						key, err = reserve(field[:i+1], field[i+1:])
						if err != nil {
							return err
						}
					case 2:
						if err := add(key, field); err != nil {
							return err
						}
					default:
						return fmt.Errorf("netstat: malformed snmp6 row")
					}
				}
				if count != 2 {
					return fmt.Errorf("netstat: malformed snmp6 row")
				}
				continue
			}
			var protocol string
			var keys []string
			for field := range strings.FieldsSeq(scanner.Text()) {
				if protocol == "" {
					if !strings.HasSuffix(field, ":") || len(field) == 1 {
						return fmt.Errorf("netstat: malformed protocol header")
					}
					protocol = strings.TrimSuffix(field, ":")
					continue
				}
				key, err := reserve(protocol, field)
				if err != nil {
					return err
				}
				keys = append(keys, key)
			}
			if len(keys) == 0 || !scanner.Scan() {
				return fmt.Errorf("netstat: missing field values")
			}
			count := 0
			for field := range strings.FieldsSeq(scanner.Text()) {
				if count == 0 {
					if field != protocol+":" {
						return fmt.Errorf("netstat: mismatched value protocol")
					}
				} else {
					if count > len(keys) {
						return fmt.Errorf("netstat: excess field values")
					}
					if err := add(keys[count-1], field); err != nil {
						return err
					}
				}
				count++
			}
			if count != len(keys)+1 {
				return fmt.Errorf("netstat: missing field values")
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("netstat: scan: %w", err)
		}
		if rows == 0 {
			return fmt.Errorf("netstat: empty file %s", read.Path)
		}
	}
	for _, metric := range metrics {
		ch <- metric
	}
	return nil
}
