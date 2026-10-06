package collectors

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
)

func init() {
	Register(Registration{Name: "netdev", OS: "linux", DefaultEnabled: true, Factory: newNetdevCollector})
}

// NetdevConfig holds the netdev collector options. Both fields are regular
// expressions. A non-empty DeviceInclude takes precedence and DeviceExclude is
// then ignored.
type NetdevConfig struct {
	DeviceExclude string
	DeviceInclude string
}

// DefaultNetdevConfig matches node_exporter's defaults.
var DefaultNetdevConfig = NetdevConfig{}

// Column order is the Linux /proc/net/dev ABI, using node_exporter's
// legacy (non-detailed) metric names.
var netdevKeys = [...]string{
	"receive_bytes", "receive_packets", "receive_errs", "receive_drop",
	"receive_fifo", "receive_frame", "receive_compressed", "receive_multicast",
	"transmit_bytes", "transmit_packets", "transmit_errs", "transmit_drop",
	"transmit_fifo", "transmit_colls", "transmit_carrier", "transmit_compressed",
}

type netdevCollector struct {
	filter  *regexp.Regexp
	include bool
	descs   [16]*prometheus.Desc
}

func newNetdevCollector(cfg Configs, _ *slog.Logger) (agentless.Collector, error) {
	c := &netdevCollector{include: cfg.Netdev.DeviceInclude != ""}
	pattern := cfg.Netdev.DeviceExclude
	if c.include {
		pattern = cfg.Netdev.DeviceInclude
	}
	if pattern != "" {
		var err error
		c.filter, err = regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("netdev device filter: %w", err)
		}
	}
	for i, key := range netdevKeys {
		c.descs[i] = prometheus.NewDesc(prometheus.BuildFQName(agentless.Namespace, "network", key+"_total"), "Network device statistic "+key+".", []string{"device"}, nil)
	}
	return c, nil
}

// Name implements agentless.Collector.
func (c *netdevCollector) Name() string { return "netdev" }

// Reads implements agentless.Collector.
func (c *netdevCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/net/dev")}
}

// Update implements agentless.Collector.
func (c *netdevCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	read := c.Reads()[0]
	// Input.Output checks transport failures; also reject NotExist on its own.
	if in[read.ID].NotExist {
		return fmt.Errorf("netdev: /proc/net/dev missing")
	}
	output, err := in.Output(read)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	if !scanner.Scan() || !strings.HasPrefix(strings.TrimSpace(scanner.Text()), "Inter-|") {
		return fmt.Errorf("netdev: missing interface header")
	}
	if !scanner.Scan() || !strings.HasPrefix(strings.TrimSpace(scanner.Text()), "face |") {
		return fmt.Errorf("netdev: missing column header")
	}
	type deviceStats struct {
		name   string
		values [16]uint64
	}
	var devices []deviceStats
	seen := map[string]bool{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		name, counters, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		fields := strings.Fields(counters)
		if !ok || name == "" || len(strings.Fields(name)) != 1 || len(fields) != len(netdevKeys) || seen[name] {
			return fmt.Errorf("netdev: malformed or duplicate device row %q", line)
		}
		seen[name] = true
		stats := deviceStats{name: name}
		for i, field := range fields {
			value, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				return fmt.Errorf("netdev device %q column %s: %w", name, netdevKeys[i], err)
			}
			stats.values[i] = value
		}
		devices = append(devices, stats)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("netdev: scan: %w", err)
	}
	// Validate the complete snapshot before emitting any metrics.
	for _, stats := range devices {
		if c.filter != nil && c.filter.MatchString(stats.name) != c.include {
			continue
		}
		for i, value := range stats.values {
			ch <- targetMetric(c.descs[i], prometheus.CounterValue, float64(value), stats.name)
		}
	}
	return nil
}
