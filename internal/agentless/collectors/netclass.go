package collectors

import (
	"bytes"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	Register(Registration{Name: "netclass", OS: "linux", DefaultEnabled: false, Factory: newNetclassCollector})
}

// These are all properties exported by the pinned node_exporter's default
// sysfs netclass collector. Unexported sysfs attributes need no reads.
var netclassNumbers = [...]struct {
	attribute, family string
	kind              prometheus.ValueType
}{
	{"addr_assign_type", "address_assign_type", prometheus.GaugeValue},
	{"carrier", "carrier", prometheus.GaugeValue},
	{"carrier_changes", "carrier_changes_total", prometheus.CounterValue},
	{"carrier_up_count", "carrier_up_changes_total", prometheus.CounterValue},
	{"carrier_down_count", "carrier_down_changes_total", prometheus.CounterValue},
	{"dev_id", "device_id", prometheus.GaugeValue},
	{"dormant", "dormant", prometheus.GaugeValue},
	{"flags", "flags", prometheus.GaugeValue},
	{"ifindex", "iface_id", prometheus.GaugeValue},
	{"iflink", "iface_link", prometheus.GaugeValue},
	{"link_mode", "iface_link_mode", prometheus.GaugeValue},
	{"mtu", "mtu_bytes", prometheus.GaugeValue},
	{"name_assign_type", "name_assign_type", prometheus.GaugeValue},
	{"netdev_group", "net_dev_group", prometheus.GaugeValue},
	{"speed", "speed_bytes", prometheus.GaugeValue},
	{"tx_queue_len", "transmit_queue_length", prometheus.GaugeValue},
	{"type", "protocol_type", prometheus.GaugeValue},
}

var netclassStrings = [...]string{"address", "broadcast", "duplex", "operstate", "ifalias"}

const netclassAttributes = len(netclassNumbers) + len(netclassStrings)

type netclassCollector struct {
	numbers  [len(netclassNumbers)]*prometheus.Desc
	up, info *prometheus.Desc
}

var _ agentless.Expander = (*netclassCollector)(nil)

func newNetclassCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	c := &netclassCollector{
		up:   prometheus.NewDesc(agentless.Namespace+"_network_up", "Value is 1 if operstate is 'up', 0 otherwise.", []string{"device"}, nil),
		info: prometheus.NewDesc(agentless.Namespace+"_network_info", "Non-numeric data from /sys/class/net/<iface>, value is always 1.", []string{"device", "address", "broadcast", "duplex", "operstate", "adminstate", "ifalias"}, nil),
	}
	for i, spec := range netclassNumbers {
		c.numbers[i] = prometheus.NewDesc(agentless.Namespace+"_network_"+spec.family, "Network device property: "+spec.family, []string{"device"}, nil)
	}
	return c, nil
}

func (*netclassCollector) Name() string { return "netclass" }
func (*netclassCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.CommandRead("ls", "-1", "/sys/class/net")}
}

func netclassRead(device, attribute string) agentless.Read {
	return agentless.FileRead("/sys/class/net/" + device + "/" + attribute)
}

// Bound rows (even invalid names), name bytes and resulting attribute reads
// before retaining names. In particular, twelve valid interfaces already
// exceed the frozen 256-read cap: reject the whole expansion, never truncate.
// Only 19 fixed families / at most 209 series can be emitted, with each label
// bounded to 4096 bytes, below the existing collector output caps.
func (c *netclassCollector) devices(in agentless.Input) ([]string, error) {
	read := c.Reads()[0]
	result := in[read.ID]
	if result.NotExist && !result.TimedOut && !result.Truncated {
		return nil, nil
	}
	output, err := in.Output(read)
	if err != nil {
		return nil, err
	}
	if len(output) == 0 {
		return nil, nil
	}
	if output[len(output)-1] != '\n' {
		return nil, fmt.Errorf("netclass: unterminated listing")
	}
	var devices []string
	rows := 0
	for row := range bytes.SplitSeq(output[:len(output)-1], []byte{'\n'}) {
		rows++
		if rows > agentless.MaxExpandedReads || len(row) > 4096 {
			return nil, fmt.Errorf("netclass: listing limit exceeded")
		}
		if len(row) == 0 {
			return nil, fmt.Errorf("netclass: empty listing row")
		}
		device := string(row)
		// bonding_masters is the bonding driver's regular control file,
		// not an interface. Upstream's ReadDir filters regular files;
		// the fixed ls listing includes this known sysfs entry.
		if device == "bonding_masters" {
			continue
		}
		// Validate the assembled read, but also require a single directory
		// entry: Validate permits slashes and a standalone dot in paths.
		if strings.Contains(device, "/") || device == "." || netclassRead(device, "address").Validate() != nil {
			continue
		}
		for _, previous := range devices {
			if previous == device {
				return nil, fmt.Errorf("netclass: duplicate device")
			}
		}
		if (len(devices)+1)*netclassAttributes > agentless.MaxExpandedReads {
			return nil, fmt.Errorf("netclass: expanded read limit exceeded")
		}
		devices = append(devices, device)
	}
	return devices, nil
}

func (c *netclassCollector) Expand(_ agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	devices, err := c.devices(in)
	if err != nil {
		return nil, err
	}
	reads := make([]agentless.Read, 0, len(devices)*netclassAttributes)
	for _, device := range devices {
		for _, spec := range netclassNumbers {
			reads = append(reads, netclassRead(device, spec.attribute))
		}
		for _, attribute := range netclassStrings {
			reads = append(reads, netclassRead(device, attribute))
		}
	}
	return reads, nil
}

func (c *netclassCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	devices, err := c.devices(in)
	if err != nil {
		return err
	}
	var metrics []prometheus.Metric
	for _, device := range devices {
		var labels [len(netclassStrings)]string
		for i, attribute := range netclassStrings {
			read := netclassRead(device, attribute)
			if in[read.ID].NotExist {
				continue
			}
			if output, err := in.Output(read); err == nil {
				value := bytes.TrimSpace(output)
				if len(value) > 4096 || !utf8.Valid(value) {
					return fmt.Errorf("netclass: invalid attribute label")
				}
				labels[i] = string(value)
			}
		}
		adminstate := "unknown"
		for i, spec := range netclassNumbers {
			read := netclassRead(device, spec.attribute)
			if in[read.ID].NotExist {
				continue
			}
			output, err := in.Output(read)
			// Sysfs commonly returns EINVAL for speed on a down link. The
			// transport cannot distinguish errno: omit just the failed
			// attribute, including absent, truncated or timed-out reads.
			if err != nil {
				continue
			}
			raw := bytes.TrimSpace(output)
			if len(raw) > 24 {
				return fmt.Errorf("netclass: numeric attribute too long")
			}
			value, err := strconv.ParseInt(string(raw), 0, 64)
			if err != nil {
				return fmt.Errorf("netclass: invalid numeric attribute %s", spec.attribute)
			}
			if spec.attribute == "flags" {
				adminstate = "down"
				if value&1 == 1 {
					adminstate = "up"
				}
			}
			number := float64(value)
			if spec.attribute == "speed" {
				// Default upstream includes unknown (-1) speeds. Multiply
				// after conversion to avoid overflowing target integers.
				number *= 1000 * 1000 / 8
			}
			metrics = append(metrics, targetMetric(c.numbers[i], spec.kind, number, device))
		}
		up := 0.0
		if labels[3] == "up" {
			up = 1
		}
		metrics = append(metrics, targetMetric(c.up, prometheus.GaugeValue, up, device),
			targetMetric(c.info, prometheus.GaugeValue, 1, device, labels[0], labels[1], labels[2], labels[3], adminstate, labels[4]))
	}
	for _, metric := range metrics {
		ch <- metric
	}
	return nil
}
