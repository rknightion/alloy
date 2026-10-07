package collectors

import (
	"bytes"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	Register(Registration{Name: "powersupplyclass", OS: "linux", DefaultEnabled: false, Factory: newPowersupplyclassCollector})
}

// Fixed exported attributes from the pinned node_exporter; never enumerate a
// supply's files or read arbitrary entries supplied by a remote listing.
var powersupplyNumbers = [...]struct {
	attribute, family string
	divisor           float64
}{
	{"authentic", "authentic", 1},
	{"calibrate", "calibrate", 1},
	{"capacity", "capacity", 1},
	{"capacity_alert_max", "capacity_alert_max", 1},
	{"capacity_alert_min", "capacity_alert_min", 1},
	{"cycle_count", "cyclecount", 1},
	{"online", "online", 1},
	{"present", "present", 1},
	{"time_to_empty_now", "time_to_empty_seconds", 1},
	{"time_to_full_now", "time_to_full_seconds", 1},
	{"current_boot", "current_boot", 1000000},
	{"current_max", "current_max", 1000000},
	{"current_now", "current_ampere", 1000000},
	{"energy_empty", "energy_empty", 1000000},
	{"energy_empty_design", "energy_empty_design", 1000000},
	{"energy_full", "energy_full", 1000000},
	{"energy_full_design", "energy_full_design", 1000000},
	{"energy_now", "energy_watthour", 1000000},
	{"voltage_boot", "voltage_boot", 1000000},
	{"voltage_max", "voltage_max", 1000000},
	{"voltage_max_design", "voltage_max_design", 1000000},
	{"voltage_min", "voltage_min", 1000000},
	{"voltage_min_design", "voltage_min_design", 1000000},
	{"voltage_now", "voltage_volt", 1000000},
	{"voltage_ocv", "voltage_ocv", 1000000},
	{"charge_control_limit", "charge_control_limit", 1000000},
	{"charge_control_limit_max", "charge_control_limit_max", 1000000},
	{"charge_counter", "charge_counter", 1000000},
	{"charge_empty", "charge_empty", 1000000},
	{"charge_empty_design", "charge_empty_design", 1000000},
	{"charge_full", "charge_full", 1000000},
	{"charge_full_design", "charge_full_design", 1000000},
	{"charge_now", "charge_ampere", 1000000},
	{"charge_term_current", "charge_term_current", 1000000},
	{"constant_charge_current", "constant_charge_current", 1000000},
	{"constant_charge_current_max", "constant_charge_current_max", 1000000},
	{"constant_charge_voltage", "constant_charge_voltage", 1000000},
	{"constant_charge_voltage_max", "constant_charge_voltage_max", 1000000},
	{"precharge_current", "precharge_current", 1000000},
	{"input_current_limit", "input_current_limit", 1000000},
	{"power_now", "power_watt", 1000000},
	{"temp", "temp_celsius", 10},
	{"temp_alert_max", "temp_alert_max_celsius", 10},
	{"temp_alert_min", "temp_alert_min_celsius", 10},
	{"temp_ambient", "temp_ambient_celsius", 10},
	{"temp_ambient_max", "temp_ambient_max_celsius", 10},
	{"temp_ambient_min", "temp_ambient_min_celsius", 10},
	{"temp_max", "temp_max_celsius", 10},
	{"temp_min", "temp_min_celsius", 10},
}
var powersupplyStrings = [...]string{"capacity_level", "charge_type", "health", "manufacturer", "model_name", "serial_number", "status", "technology", "type", "usb_type", "scope"}

const powersupplyAttributes = len(powersupplyNumbers) + len(powersupplyStrings)

type powersupplyclassCollector struct {
	numbers [len(powersupplyNumbers)]*prometheus.Desc
}

var _ agentless.Expander = (*powersupplyclassCollector)(nil)

func newPowersupplyclassCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	c := &powersupplyclassCollector{}
	for i, spec := range powersupplyNumbers {
		c.numbers[i] = prometheus.NewDesc(agentless.Namespace+"_power_supply_"+spec.family, spec.family+" value of /sys/class/power_supply/<power_supply>.", []string{"power_supply"}, nil)
	}
	return c, nil
}
func (*powersupplyclassCollector) Name() string { return "powersupplyclass" }
func (*powersupplyclassCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.CommandRead("ls", "-1", "/sys/class/power_supply")}
}
func powersupplyRead(device, attribute string) agentless.Read {
	return agentless.FileRead("/sys/class/power_supply/" + device + "/" + attribute)
}
func (c *powersupplyclassCollector) devices(in agentless.Input) ([]string, error) {
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
		return nil, fmt.Errorf("powersupply: unterminated listing")
	}
	var devices []string
	rows := 0
	for row := range bytes.SplitSeq(output[:len(output)-1], []byte{'\n'}) {
		rows++
		if rows > agentless.MaxExpandedReads || len(row) > 4096 {
			return nil, fmt.Errorf("powersupply: listing limit exceeded")
		}
		if len(row) == 0 {
			return nil, fmt.Errorf("powersupply: empty listing row")
		}
		device := string(row)
		// Validate the assembled read, but also require a single directory
		// entry: Validate permits slashes and a standalone dot in paths.
		if strings.Contains(device, "/") || device == "." || powersupplyRead(device, "type").Validate() != nil {
			continue
		}
		for _, previous := range devices {
			if previous == device {
				return nil, fmt.Errorf("powersupply: duplicate device")
			}
		}
		if (len(devices)+1)*powersupplyAttributes > agentless.MaxExpandedReads {
			return nil, fmt.Errorf("powersupply: expanded read limit exceeded")
		}
		devices = append(devices, device)
	}
	return devices, nil
}

func (c *powersupplyclassCollector) Expand(_ agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	devices, err := c.devices(in)
	if err != nil {
		return nil, err
	}
	reads := make([]agentless.Read, 0, len(devices)*powersupplyAttributes)
	for _, device := range devices {
		for _, spec := range powersupplyNumbers {
			read := powersupplyRead(device, spec.attribute)
			if err := read.Validate(); err != nil {
				return nil, err
			}
			reads = append(reads, read)
		}
		for _, attribute := range powersupplyStrings {
			read := powersupplyRead(device, attribute)
			if err := read.Validate(); err != nil {
				return nil, err
			}
			reads = append(reads, read)
		}
	}
	return reads, nil
}

// Transport failures fail only this collector, without publishing partial
// metrics. Missing and malformed attributes are isolated to that attribute.
func (c *powersupplyclassCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	devices, err := c.devices(in)
	if err != nil {
		return err
	}
	var metrics []prometheus.Metric
	for _, device := range devices {
		for i, spec := range powersupplyNumbers {
			read := powersupplyRead(device, spec.attribute)
			result := in[read.ID]
			if result.NotExist && !result.TimedOut && !result.Truncated {
				continue
			}
			output, err := in.Output(read)
			if err != nil {
				return err
			}
			raw := bytes.TrimSpace(output)
			if len(raw) > 20 {
				continue
			}
			value, err := strconv.ParseInt(string(raw), 10, 64)
			if err != nil {
				continue
			}
			metrics = append(metrics, targetMetric(c.numbers[i], prometheus.GaugeValue, float64(value)/spec.divisor, device))
		}
		keys, values := []string{"power_supply"}, []string{device}
		for _, attribute := range powersupplyStrings {
			read := powersupplyRead(device, attribute)
			result := in[read.ID]
			if result.NotExist && !result.TimedOut && !result.Truncated {
				continue
			}
			output, err := in.Output(read)
			if err != nil {
				return err
			}
			raw := bytes.TrimSpace(output)
			if len(raw) == 0 || len(raw) > 4096 {
				continue
			}
			keys = append(keys, attribute)
			values = append(values, strings.ToValidUTF8(string(raw), "�"))
		}
		desc := prometheus.NewDesc(agentless.Namespace+"_power_supply_info", "info of /sys/class/power_supply/<power_supply>.", keys, nil)
		metrics = append(metrics, targetMetric(desc, prometheus.GaugeValue, 1, values...))
	}
	for _, metric := range metrics {
		ch <- metric
	}
	return nil
}
