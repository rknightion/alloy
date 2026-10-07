package collectors

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	Register(Registration{Name: "arp", OS: "linux", DefaultEnabled: true, Factory: newARPCollector})
}

type arpCollector struct{ entries *prometheus.Desc }

func newARPCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &arpCollector{entries: prometheus.NewDesc(agentless.Namespace+"_arp_entries", "ARP entries by device", []string{"device"}, nil)}, nil
}

func (*arpCollector) Name() string { return "arp" }
func (*arpCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/net/arp")}
}

func (c *arpCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	read := c.Reads()[0]
	result := in[read.ID]
	if result.NotExist && !result.TimedOut && !result.Truncated {
		return nil
	}
	output, err := in.Output(read)
	if err != nil {
		return err
	}
	entries, err := parseARPCounts(output)
	if err != nil {
		return err
	}
	for device, count := range entries {
		ch <- prometheus.MustNewConstMetric(c.entries, prometheus.GaugeValue, float64(count), device)
	}
	return nil
}

// Mirror procfs v0.22.0's ARP row contract without allocating its unbounded
// line/column/entry slices. Blank and nine-column header rows are ignored;
// six-column rows validate MAC and byte flags (procfs does not reject invalid
// IPs, hardware types or masks). Only counts are retained, not individual rows.
// Before retention, bound tokens, escaped device labels and distinct devices
// to the frozen 4096-label-byte and 20000-series caps. Only one family is emitted.
// Netlink and device filters are deliberately not ported; no other ARP families
// are present in the pinned exporter.
func parseARPCounts(output []byte) (map[string]uint32, error) {
	entries := make(map[string]uint32)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 4096), 40*1024)
	for scanner.Scan() {
		var columns [9][]byte
		width := 0
		for token := range bytes.FieldsSeq(scanner.Bytes()) {
			if width == len(columns) || len(token) > 4096 {
				return nil, fmt.Errorf("arp: column limit exceeded")
			}
			columns[width] = token
			width++
		}
		if width == 0 || width == 9 {
			continue
		}
		if width != 6 {
			return nil, fmt.Errorf("arp: invalid row width")
		}
		if _, err := net.ParseMAC(string(columns[3])); err != nil {
			return nil, fmt.Errorf("arp: invalid MAC: %w", err)
		}
		if _, err := strconv.ParseUint(string(columns[2]), 0, 8); err != nil {
			return nil, fmt.Errorf("arp: invalid flags: %w", err)
		}
		device := targetLabel(string(columns[5]))
		if len(device) > 4096 {
			return nil, fmt.Errorf("arp: label limit exceeded")
		}
		if _, exists := entries[device]; !exists && len(entries) == 20000 {
			return nil, fmt.Errorf("arp: series limit exceeded")
		}
		entries[device]++
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("arp: scan: %w", err)
	}
	return entries, nil
}
