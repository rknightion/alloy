package collectors

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	Register(Registration{Name: "sockstat", OS: "linux", DefaultEnabled: true, Factory: newSockstatCollector})
}

type sockstatCollector struct{}

func newSockstatCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &sockstatCollector{}, nil
}

func (*sockstatCollector) Name() string { return "sockstat" }

func (*sockstatCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/net/sockstat"), agentless.FileRead("/proc/net/sockstat6"), agentless.CommandRead("getconf", "PAGESIZE")}
}

// There are no labels and one series per family. Bound both parsing state
// (including unknown fields) and emitted families before retention, below the
// frozen 500-family/20000-series caps. Token iteration never allocates a slice
// proportional to a target line.
const maxSockstatFields = 500

func (c *sockstatCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	reads := c.Reads()
	var pageSize int64
	if output, err := in.Output(reads[2]); err == nil {
		raw := bytes.TrimSpace(output)
		if len(raw) <= 20 {
			if value, err := strconv.ParseInt(string(raw), 10, 64); err == nil && value > 0 {
				pageSize = value
			}
		}
	}
	var metrics []prometheus.Metric
	seen := make(map[string]bool)
	fields, rows := 0, 0
	add := func(protocol, field string, value float64) error {
		if len(metrics) == maxSockstatFields {
			return fmt.Errorf("sockstat: family limit exceeded")
		}
		name := protocol + "_" + field
		if seen[name] {
			return fmt.Errorf("sockstat: duplicate family")
		}
		seen[name] = true
		help := "Number of " + protocol + " sockets in state " + field + "."
		if protocol == "sockets" {
			help = "Number of IPv4 sockets in use."
		}
		metric, err := prometheus.NewConstMetric(prometheus.NewDesc(agentless.Namespace+"_sockstat_"+name, help, nil, nil), prometheus.GaugeValue, value)
		if err != nil {
			return err
		}
		metrics = append(metrics, metric)
		return nil
	}
	for index, read := range reads[:2] {
		result := in[read.ID]
		if result.NotExist && !result.TimedOut && !result.Truncated {
			continue
		}
		output, err := in.Output(read)
		if err != nil {
			return err
		}
		scanner := bufio.NewScanner(bytes.NewReader(output))
		fileRows := 0
		for scanner.Scan() {
			rows++
			fileRows++
			if rows > maxSockstatFields {
				return fmt.Errorf("sockstat: row limit exceeded")
			}
			var protocol, key string
			count := 0
			var values [7]int64
			var present [7]bool
			for token := range strings.FieldsSeq(scanner.Text()) {
				if len(token) > 4096 {
					return fmt.Errorf("sockstat: token too long")
				}
				if count == 0 {
					if !strings.HasSuffix(token, ":") {
						return fmt.Errorf("sockstat: malformed protocol")
					}
					protocol = strings.TrimSuffix(token, ":")
					if !validMeminfoKey(protocol) {
						return fmt.Errorf("sockstat: invalid protocol")
					}
				} else if count%2 == 1 {
					fields++
					if fields > maxSockstatFields || !validMeminfoKey(token) {
						return fmt.Errorf("sockstat: invalid or excessive fields")
					}
					key = token
				} else {
					value, err := strconv.ParseInt(token, 10, 64)
					if err != nil {
						return fmt.Errorf("sockstat: invalid value")
					}
					slot := sockstatFieldIndex(key)
					if slot >= 0 {
						if present[slot] {
							return fmt.Errorf("sockstat: duplicate field")
						}
						values[slot], present[slot] = value, true
					}
				}
				count++
			}
			if count < 3 || count%2 != 1 {
				return fmt.Errorf("sockstat: malformed row")
			}
			if protocol == "sockets" {
				if !present[6] {
					return fmt.Errorf("sockstat: missing used")
				}
				if index == 0 {
					if err := add(protocol, "used", float64(values[6])); err != nil {
						return err
					}
				}
				continue
			}
			// Upstream always exports inuse, defaulting to zero if absent. Other
			// known fields are optional; unknown fields are validated but not emitted.
			for slot, field := range [...]string{"inuse", "orphan", "tw", "alloc", "mem", "memory"} {
				if slot != 0 && !present[slot] {
					continue
				}
				if err := add(protocol, field, float64(values[slot])); err != nil {
					return err
				}
			}
			if present[4] && pageSize > 0 {
				// Multiply as float64 to avoid overflowing an integer byte count.
				if err := add(protocol, "mem_bytes", float64(values[4])*float64(pageSize)); err != nil {
					return err
				}
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("sockstat: scan: %w", err)
		}
		if fileRows == 0 {
			return fmt.Errorf("sockstat: empty file")
		}
	}
	for _, metric := range metrics {
		ch <- metric
	}
	return nil
}

func sockstatFieldIndex(key string) int {
	switch key {
	case "inuse":
		return 0
	case "orphan":
		return 1
	case "tw":
		return 2
	case "alloc":
		return 3
	case "mem":
		return 4
	case "memory":
		return 5
	case "used":
		return 6
	default:
		return -1
	}
}
