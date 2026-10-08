// Copyright 2017-2019 The Prometheus Authors
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
	Register(Registration{Name: "infiniband", OS: "linux", DefaultEnabled: false, Factory: newInfinibandCollector})
}

const infinibandRoot = "/sys/class/infiniband"

// Attribute/family mappings and help strings follow the pinned node_exporter
// collector/infiniband_linux.go (Apache-2.0, Prometheus Authors).
var infinibandSpecs = [...]struct {
	attribute, family, help string
	kind                    prometheus.ValueType
	scale                   uint64
}{
	{"counters_ext/port_multicast_rcv_packets", "legacy_multicast_packets_received_total", "Number of multicast packets received", prometheus.CounterValue, 1},
	{"counters_ext/port_multicast_xmit_packets", "legacy_multicast_packets_transmitted_total", "Number of multicast packets transmitted", prometheus.CounterValue, 1},
	{"counters_ext/port_rcv_data_64", "legacy_data_received_bytes_total", "Number of data octets received on all links", prometheus.CounterValue, 4},
	{"counters_ext/port_rcv_packets_64", "legacy_packets_received_total", "Number of data packets received on all links", prometheus.CounterValue, 1},
	{"counters_ext/port_unicast_rcv_packets", "legacy_unicast_packets_received_total", "Number of unicast packets received", prometheus.CounterValue, 1},
	{"counters_ext/port_unicast_xmit_packets", "legacy_unicast_packets_transmitted_total", "Number of unicast packets transmitted", prometheus.CounterValue, 1},
	{"counters_ext/port_xmit_data_64", "legacy_data_transmitted_bytes_total", "Number of data octets transmitted on all links", prometheus.CounterValue, 4},
	{"counters_ext/port_xmit_packets_64", "legacy_packets_transmitted_total", "Number of data packets received on all links", prometheus.CounterValue, 1},
	{"counters/link_downed", "link_downed_total", "Number of times the link failed to recover from an error state and went down", prometheus.CounterValue, 1},
	{"counters/link_error_recovery", "link_error_recovery_total", "Number of times the link successfully recovered from an error state", prometheus.CounterValue, 1},
	{"counters/multicast_rcv_packets", "multicast_packets_received_total", "Number of multicast packets received (including errors)", prometheus.CounterValue, 1},
	{"counters/multicast_xmit_packets", "multicast_packets_transmitted_total", "Number of multicast packets transmitted (including errors)", prometheus.CounterValue, 1},
	{"counters/port_rcv_constraint_errors", "port_constraint_errors_received_total", "Number of packets received on the switch physical port that are discarded", prometheus.CounterValue, 1},
	{"counters/port_xmit_constraint_errors", "port_constraint_errors_transmitted_total", "Number of packets not transmitted from the switch physical port", prometheus.CounterValue, 1},
	{"counters/port_rcv_data", "port_data_received_bytes_total", "Number of data octets received on all links", prometheus.CounterValue, 4},
	{"counters/port_xmit_data", "port_data_transmitted_bytes_total", "Number of data octets transmitted on all links", prometheus.CounterValue, 4},
	{"counters/port_rcv_discards", "port_discards_received_total", "Number of inbound packets discarded by the port because the port is down or congested", prometheus.CounterValue, 1},
	{"counters/port_xmit_discards", "port_discards_transmitted_total", "Number of outbound packets discarded by the port because the port is down or congested", prometheus.CounterValue, 1},
	{"counters/port_rcv_errors", "port_errors_received_total", "Number of packets containing an error that were received on this port", prometheus.CounterValue, 1},
	{"counters/port_rcv_packets", "port_packets_received_total", "Number of packets received on all VLs by this port (including errors)", prometheus.CounterValue, 1},
	{"counters/port_xmit_packets", "port_packets_transmitted_total", "Number of packets transmitted on all VLs from this port (including errors)", prometheus.CounterValue, 1},
	{"counters/port_xmit_wait", "port_transmit_wait_total", "Number of ticks during which the port had data to transmit but no data was sent during the entire tick", prometheus.CounterValue, 1},
	{"counters/unicast_rcv_packets", "unicast_packets_received_total", "Number of unicast packets received (including errors)", prometheus.CounterValue, 1},
	{"counters/unicast_xmit_packets", "unicast_packets_transmitted_total", "Number of unicast packets transmitted (including errors)", prometheus.CounterValue, 1},
	{"state", "state_id", "State of the InfiniBand port (0: no change, 1: down, 2: init, 3: armed, 4: active, 5: act defer)", prometheus.GaugeValue, 1},
	{"phys_state", "physical_state_id", "Physical state of the InfiniBand port (0: no change, 1: sleep, 2: polling, 3: disable, 4: shift, 5: link up, 6: link error recover, 7: phytest)", prometheus.GaugeValue, 1},
	{"rate", "rate_bytes_per_second", "Maximum signal transfer rate", prometheus.GaugeValue, 1},
}

var infinibandInfoAttributes = [...]string{"board_id", "fw_ver", "hca_type"}

type infinibandCollector struct {
	desc []*prometheus.Desc
	info *prometheus.Desc
}

var _ agentless.DeepExpander = (*infinibandCollector)(nil)

func newInfinibandCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	c := &infinibandCollector{info: prometheus.NewDesc(agentless.Namespace+"_infiniband_info", "Non-numeric data from /sys/class/infiniband/<device>, value is always 1.", []string{"device", "board_id", "firmware_version", "hca_type"}, nil)}
	for _, spec := range infinibandSpecs {
		c.desc = append(c.desc, prometheus.NewDesc(agentless.Namespace+"_infiniband_"+spec.family, spec.help, []string{"device", "port"}, nil))
	}
	return c, nil
}
func (*infinibandCollector) Name() string { return "infiniband" }
func (*infinibandCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.CommandRead("ls", "-1", infinibandRoot)}
}
func infinibandListing(device string) agentless.Read {
	return agentless.CommandRead("ls", "-1", infinibandRoot+"/"+device+"/ports")
}
func infinibandRead(device, port, attribute string) agentless.Read {
	path := infinibandRoot + "/" + device
	if port != "" {
		path += "/ports/" + port
	}
	return agentless.FileRead(path + "/" + attribute)
}
func infinibandOutput(in agentless.Input, read agentless.Read) ([]byte, bool, error) {
	if err := read.Validate(); err != nil {
		return nil, false, err
	}
	res := in[read.ID]
	if res.NotExist && !res.TimedOut && !res.Truncated {
		return nil, false, nil
	}
	output, err := in.Output(read)
	return output, true, err
}

// Check row and expansion bounds before retaining names. Device names use the
// read-path alphabet; ports are canonical uint32s so distinct paths cannot
// collapse onto the same upstream port label. Neither can introduce traversal.
func infinibandNames(in agentless.Input, read agentless.Read, ports bool, limit int) ([]string, error) {
	output, _, err := infinibandOutput(in, read)
	if err != nil {
		return nil, err
	}
	if len(output) == 0 {
		return nil, nil
	}
	if output[len(output)-1] != '\n' {
		return nil, fmt.Errorf("infiniband: unterminated listing")
	}
	var names []string
	rows := 0
	for row := range bytes.SplitSeq(output[:len(output)-1], []byte{'\n'}) {
		rows++
		if rows > agentless.MaxExpandedReads || len(row) == 0 || len(row) > 4096 || len(names) >= limit {
			return nil, fmt.Errorf("infiniband: listing limit exceeded")
		}
		if bytes.Equal(row, []byte(".")) || bytes.Contains(row, []byte("..")) {
			return nil, fmt.Errorf("infiniband: unsafe entry")
		}
		for _, b := range row {
			if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-' || b == '.') {
				return nil, fmt.Errorf("infiniband: unsafe entry")
			}
		}
		if ports {
			if len(row) > 10 {
				return nil, fmt.Errorf("infiniband: invalid port")
			}
			n, err := strconv.ParseUint(string(row), 10, 32)
			if err != nil || strconv.FormatUint(n, 10) != string(row) {
				return nil, fmt.Errorf("infiniband: invalid port")
			}
		}
		name := string(row)
		for _, previous := range names {
			if previous == name {
				return nil, fmt.Errorf("infiniband: duplicate entry")
			}
		}
		names = append(names, name)
	}
	return names, nil
}
func (c *infinibandCollector) devices(in agentless.Input) ([]string, error) {
	return infinibandNames(in, c.Reads()[0], false, min(agentless.MaxDeepListings, agentless.MaxExpandedReads/(1+len(infinibandInfoAttributes))))
}
func (c *infinibandCollector) Expand(_ agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	devices, err := c.devices(in)
	if err != nil {
		return nil, err
	}
	var reads []agentless.Read
	for _, device := range devices {
		reads = append(reads, infinibandListing(device))
		for _, attr := range infinibandInfoAttributes {
			reads = append(reads, infinibandRead(device, "", attr))
		}
	}
	for _, read := range reads {
		if err := read.Validate(); err != nil {
			return nil, err
		}
	}
	return reads, nil
}
func (c *infinibandCollector) ExpandDeep(_ agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	devices, err := c.devices(in)
	if err != nil {
		return nil, err
	}
	budget := agentless.MaxExpandedReads - len(devices)*(1+len(infinibandInfoAttributes))
	var reads []agentless.Read
	for _, device := range devices {
		ports, err := infinibandNames(in, infinibandListing(device), true, (budget-len(reads))/len(infinibandSpecs))
		if err != nil {
			return nil, err
		}
		for _, port := range ports {
			for _, spec := range infinibandSpecs {
				read := infinibandRead(device, port, spec.attribute)
				if err := read.Validate(); err != nil {
					return nil, err
				}
				reads = append(reads, read)
			}
		}
	}
	return reads, nil
}
func infinibandValue(raw []byte, attr string) (uint64, error) {
	if len(raw) > 256 {
		return 0, fmt.Errorf("infiniband: oversized attribute")
	}
	s := strings.TrimSpace(string(raw))
	switch attr {
	case "state", "phys_state":
		id, name, ok := strings.Cut(s, ":")
		if !ok || strings.TrimSpace(name) == "" || strings.Contains(name, ":") {
			return 0, fmt.Errorf("infiniband: malformed state")
		}
		return strconv.ParseUint(strings.TrimSpace(id), 10, 32)
	case "rate":
		number, unit, ok := strings.Cut(s, " ")
		if !ok || !strings.HasPrefix(unit, "Gb/sec") {
			return 0, fmt.Errorf("infiniband: malformed rate")
		}
		rate, err := strconv.ParseFloat(number, 32)
		if err != nil || math.IsNaN(rate) || math.IsInf(rate, 0) || rate < 0 || rate*125000000 >= math.Exp2(64) {
			return 0, fmt.Errorf("infiniband: invalid rate")
		}
		return uint64(rate * 125000000), nil
	default:
		if len(s) > 20 {
			return 0, fmt.Errorf("infiniband: oversized counter")
		}
		return strconv.ParseUint(s, 10, 64)
	}
}
func (c *infinibandCollector) Update(target agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	devices, err := c.devices(in)
	if err != nil {
		return err
	}
	// Revalidate the complete shared expansion before retaining any series.
	deep, err := c.ExpandDeep(target, in)
	if err != nil {
		return err
	}
	var metrics []prometheus.Metric
	for _, device := range devices {
		labels := []string{device}
		present := true
		for _, attr := range infinibandInfoAttributes {
			output, exists, err := infinibandOutput(in, infinibandRead(device, "", attr))
			if err != nil {
				return err
			}
			if len(output) > 256 {
				return fmt.Errorf("infiniband: oversized info attribute")
			}
			present = present && exists
			labels = append(labels, string(bytes.TrimSpace(output)))
		}
		if present {
			metrics = append(metrics, targetMetric(c.info, prometheus.GaugeValue, 1, labels...))
		}
	}
	for i, read := range deep {
		specIndex := i % len(infinibandSpecs)
		spec := infinibandSpecs[specIndex]
		output, exists, err := infinibandOutput(in, read)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		if len(output) > 256 {
			return fmt.Errorf("infiniband: oversized attribute")
		}
		// Old drivers expose this literal instead of an unavailable PMA counter.
		if spec.kind == prometheus.CounterValue && bytes.Equal(bytes.TrimSpace(output), []byte("N/A (no PMA)")) {
			continue
		}
		value, err := infinibandValue(output, spec.attribute)
		if err != nil {
			return fmt.Errorf("infiniband: invalid %s: %w", read.Path, err)
		}
		parts := strings.Split(strings.TrimPrefix(read.Path, infinibandRoot+"/"), "/")
		metrics = append(metrics, targetMetric(c.desc[specIndex], spec.kind, float64(value*spec.scale), parts[0], parts[2]))
	}
	for _, metric := range metrics {
		ch <- metric
	}
	return nil
}
