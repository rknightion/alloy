package collectors

import (
	"bytes"
	"fmt"
	"log/slog"
	"unicode/utf8"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	Register(Registration{Name: "nvme", OS: "linux", DefaultEnabled: true, Factory: newNVMeCollector})
}

// node_exporter exports the four info labels below. Also read the requested
// controller attribute cntlid, which is not an upstream metric or present in
// its fixture. Namespace properties are not exported, so no namespace
// enumeration or namespace attribute reads are needed.
var nvmeAttributes = [...]string{"firmware_rev", "model", "serial", "state", "cntlid"}

type nvmeCollector struct{ info *prometheus.Desc }

var _ agentless.Expander = (*nvmeCollector)(nil)

func newNVMeCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &nvmeCollector{info: prometheus.NewDesc(agentless.Namespace+"_nvme_info", "Non-numeric data from /sys/class/nvme/<device>, value is always 1.", []string{"device", "firmware_revision", "model", "serial", "state"}, nil)}, nil
}
func (*nvmeCollector) Name() string { return "nvme" }
func (*nvmeCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.CommandRead("ls", "-1", "/sys/class/nvme")}
}
func nvmeRead(device, attribute string) agentless.Read {
	return agentless.FileRead("/sys/class/nvme/" + device + "/" + attribute)
}

func (c *nvmeCollector) devices(in agentless.Input) ([]string, error) {
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
		return nil, fmt.Errorf("nvme: unterminated listing")
	}
	var devices []string
	rows := 0
	for row := range bytes.SplitSeq(output[:len(output)-1], []byte{'\n'}) {
		rows++
		// Bound even invalid entries before allocating/retaining their strings.
		if rows > agentless.MaxExpandedReads || len(row) > 4096 {
			return nil, fmt.Errorf("nvme: listing limit exceeded")
		}
		if len(row) == 0 {
			return nil, fmt.Errorf("nvme: empty listing row")
		}
		if len(row) <= 4 || !bytes.HasPrefix(row, []byte("nvme")) {
			continue
		}
		valid := true
		for _, b := range row[4:] {
			if b < '0' || b > '9' {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		if (len(devices)+1)*len(nvmeAttributes) > agentless.MaxExpandedReads {
			return nil, fmt.Errorf("nvme: expanded read limit exceeded")
		}
		device := string(row)
		for _, previous := range devices {
			if previous == device {
				return nil, fmt.Errorf("nvme: duplicate device")
			}
		}
		devices = append(devices, device)
	}
	return devices, nil
}
func (c *nvmeCollector) Expand(_ agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	devices, err := c.devices(in)
	if err != nil {
		return nil, err
	}
	reads := make([]agentless.Read, 0, len(devices)*len(nvmeAttributes))
	for _, device := range devices {
		for _, attribute := range nvmeAttributes {
			read := nvmeRead(device, attribute)
			if err := read.Validate(); err != nil {
				return nil, err
			}
			reads = append(reads, read)
		}
	}
	return reads, nil
}
func (c *nvmeCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	devices, err := c.devices(in)
	if err != nil {
		return err
	}
	var metrics []prometheus.Metric
	for _, device := range devices {
		var labels [4]string
		usable := true
		for i, attribute := range nvmeAttributes {
			read := nvmeRead(device, attribute)
			if err := read.Validate(); err != nil {
				return err
			}
			result := in[read.ID]
			if result.NotExist && !result.TimedOut && !result.Truncated {
				// Missing unexported cntlid (including the upstream fixture) cannot
				// affect the info labels. Missing exported attributes omit this device.
				if i < len(labels) {
					usable = false
				}
				continue
			}
			output, err := in.Output(read)
			if err != nil {
				return err
			}
			// Check bytes before retaining a label. Reject the collector atomically
			// on malformed attributes, without affecting sibling collectors.
			if len(output) > 4096 || !utf8.Valid(output) || bytes.IndexByte(output, 0) >= 0 {
				return fmt.Errorf("nvme: invalid attribute %s for %s", attribute, device)
			}
			if i < len(labels) {
				labels[i] = string(bytes.TrimSpace(output))
			}
		}
		if usable {
			metrics = append(metrics, targetMetric(c.info, prometheus.GaugeValue, 1, device, labels[0], labels[1], labels[2], labels[3]))
		}
	}
	for _, metric := range metrics {
		ch <- metric
	}
	return nil
}
