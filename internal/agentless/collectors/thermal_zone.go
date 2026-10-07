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

const thermalZoneName = "thermal_zone"

func init() {
	Register(Registration{Name: thermalZoneName, OS: "linux", DefaultEnabled: false, Factory: newThermalZoneCollector})
}

var thermalZoneAttributes = [...]string{"type", "temp", "policy", "mode"}
var thermalCoolingAttributes = [...]string{"type", "cur_state", "max_state"}

type thermalZoneCollector struct{ temp, current, maximum *prometheus.Desc }

var _ agentless.Expander = (*thermalZoneCollector)(nil)

func newThermalZoneCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &thermalZoneCollector{
		temp:    prometheus.NewDesc(agentless.Namespace+"_thermal_zone_temp", "Zone temperature in Celsius", []string{"zone", "type"}, nil),
		current: prometheus.NewDesc(agentless.Namespace+"_cooling_device_cur_state", "Current throttle state of the cooling device", []string{"name", "type"}, nil),
		maximum: prometheus.NewDesc(agentless.Namespace+"_cooling_device_max_state", "Maximum throttle state of the cooling device", []string{"name", "type"}, nil),
	}, nil
}
func (*thermalZoneCollector) Name() string { return thermalZoneName }
func (*thermalZoneCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.CommandRead("ls", "-1", "/sys/class/thermal")}
}
func thermalRead(device, attribute string) agentless.Read {
	return agentless.FileRead("/sys/class/thermal/" + device + "/" + attribute)
}
func thermalAttributes(device string) []string {
	if strings.HasPrefix(device, thermalZoneName) {
		return thermalZoneAttributes[:]
	}
	return thermalCoolingAttributes[:]
}

// Scan rows and names before retaining them. Both invalid rows and all fixed
// attribute reads count towards the frozen expansion bound; never truncate.
func (c *thermalZoneCollector) devices(in agentless.Input) ([]string, error) {
	read := c.Reads()[0]
	if err := read.Validate(); err != nil {
		return nil, err
	}
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
		return nil, fmt.Errorf("thermal_zone: unterminated listing")
	}
	var devices []string
	rows, reads := 0, 0
	for row := range bytes.SplitSeq(output[:len(output)-1], []byte{'\n'}) {
		rows++
		if rows > agentless.MaxExpandedReads || len(row) > 128 {
			return nil, fmt.Errorf("thermal_zone: listing limit exceeded")
		}
		if len(row) == 0 {
			return nil, fmt.Errorf("thermal_zone: empty listing row")
		}
		prefix := thermalZoneName
		if !bytes.HasPrefix(row, []byte(prefix)) {
			prefix = "cooling_device"
		}
		if !bytes.HasPrefix(row, []byte(prefix)) || len(row) == len(prefix) {
			continue
		}
		valid := true
		for _, b := range row[len(prefix):] {
			if b < '0' || b > '9' {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		device := string(row)
		if err := thermalRead(device, "type").Validate(); err != nil {
			return nil, err
		}
		for _, previous := range devices {
			if previous == device {
				return nil, fmt.Errorf("thermal_zone: duplicate device")
			}
		}
		reads += len(thermalAttributes(device))
		if reads > agentless.MaxExpandedReads {
			return nil, fmt.Errorf("thermal_zone: expanded read limit exceeded")
		}
		devices = append(devices, device)
	}
	return devices, nil
}
func (c *thermalZoneCollector) Expand(_ agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	devices, err := c.devices(in)
	if err != nil {
		return nil, err
	}
	var reads []agentless.Read
	for _, device := range devices {
		for _, attribute := range thermalAttributes(device) {
			read := thermalRead(device, attribute)
			if err := read.Validate(); err != nil {
				return nil, err
			}
			reads = append(reads, read)
		}
	}
	return reads, nil
}

// Missing files and malformed attributes are isolated. Transport failures fail
// this collector atomically. Bounds apply before string conversion or retention.
func thermalAttribute(in agentless.Input, read agentless.Read, numeric bool) (string, bool, error) {
	if err := read.Validate(); err != nil {
		return "", false, err
	}
	result := in[read.ID]
	if result.NotExist && !result.TimedOut && !result.Truncated {
		return "", false, nil
	}
	output, err := in.Output(read)
	if err != nil {
		return "", false, err
	}
	limit := 4096
	if numeric {
		limit = 24
	}
	if len(output) > limit+1 {
		return "", false, nil
	}
	raw := bytes.TrimSpace(output)
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return "", false, nil
	}
	return string(raw), true, nil
}
func (c *thermalZoneCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	devices, err := c.devices(in)
	if err != nil {
		return err
	}
	var metrics []prometheus.Metric
	for _, device := range devices {
		attributes := thermalAttributes(device)
		var values [4]string
		var present [4]bool
		for i, attribute := range attributes {
			values[i], present[i], err = thermalAttribute(in, thermalRead(device, attribute), attribute == "temp" || attribute == "cur_state" || attribute == "max_state")
			if err != nil {
				return err
			}
		}
		if !present[0] {
			continue
		}
		zone := strings.HasPrefix(device, thermalZoneName)
		prefix := "cooling_device"
		if zone {
			prefix = thermalZoneName
		}
		name := strings.TrimPrefix(device, prefix)
		end := 3
		if zone {
			end = 2
		}
		for i := 1; i < end; i++ {
			if !present[i] {
				continue
			}
			value, err := strconv.ParseInt(values[i], 10, 64)
			if err != nil {
				continue
			}
			desc, number := c.current, float64(value)
			if zone {
				desc = c.temp
				number /= 1000
			} else if i == 2 {
				desc = c.maximum
			}
			metrics = append(metrics, targetMetric(desc, prometheus.GaugeValue, number, name, values[0]))
		}
	}
	for _, metric := range metrics {
		ch <- metric
	}
	return nil
}
