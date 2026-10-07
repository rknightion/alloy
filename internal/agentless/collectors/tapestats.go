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

const tapestatsName = "tapestats"

func init() {
	Register(Registration{Name: tapestatsName, OS: "linux", DefaultEnabled: false, Factory: newTapestatsCollector})
}

// All ten families exported by the pinned node_exporter are included.
var tapestatsAttributes = [...]struct {
	attribute, family, help string
	scale                   float64
	kind                    prometheus.ValueType
}{
	{"in_flight", "io_now", "The number of I/Os currently outstanding to this device.", 1, prometheus.GaugeValue},
	{"io_ns", "io_time_seconds_total", "The amount of time spent waiting for all I/O to complete (including read and write). This includes tape movement commands such as seeking between file or set marks and implicit tape movement such as when rewind on close tape devices are used.", 1e-9, prometheus.CounterValue},
	{"other_cnt", "io_others_total", "The number of I/Os issued to the tape drive other than read or write commands. The time taken to complete these commands uses the following calculation io_time_seconds_total-read_time_seconds_total-write_time_seconds_total", 1, prometheus.CounterValue},
	{"read_byte_cnt", "read_bytes_total", "The number of bytes read from the tape drive.", 1, prometheus.CounterValue},
	{"read_cnt", "reads_completed_total", "The number of read requests issued to the tape drive.", 1, prometheus.CounterValue},
	{"read_ns", "read_time_seconds_total", "The amount of time spent waiting for read requests to complete.", 1e-9, prometheus.CounterValue},
	{"resid_cnt", "residual_total", "The number of times during a read or write we found the residual amount to be non-zero. This should mean that a program is issuing a read larger thean the block size on tape. For write not all data made it to tape.", 1, prometheus.CounterValue},
	{"write_byte_cnt", "written_bytes_total", "The number of bytes written to the tape drive.", 1, prometheus.CounterValue},
	{"write_cnt", "writes_completed_total", "The number of write requests issued to the tape drive.", 1, prometheus.CounterValue},
	{"write_ns", "write_time_seconds_total", "The amount of time spent waiting for write requests to complete.", 1e-9, prometheus.CounterValue},
}

type tapestatsCollector struct {
	descs [len(tapestatsAttributes)]*prometheus.Desc
}

var _ agentless.Expander = (*tapestatsCollector)(nil)

func newTapestatsCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	c := &tapestatsCollector{}
	for i, spec := range tapestatsAttributes {
		c.descs[i] = prometheus.NewDesc(agentless.Namespace+"_tape_"+spec.family, spec.help, []string{"device"}, nil)
	}
	return c, nil
}
func (*tapestatsCollector) Name() string { return tapestatsName }
func (*tapestatsCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.CommandRead("ls", "-1", "/sys/class/scsi_tape")}
}
func tapestatsRead(device, attribute string) agentless.Read {
	return agentless.FileRead("/sys/class/scsi_tape/" + device + "/stats/" + attribute)
}

func (c *tapestatsCollector) devices(in agentless.Input) ([]string, error) {
	read := c.Reads()[0]
	result := in[read.ID]
	if result.NotExist && !result.Truncated && !result.TimedOut {
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
		return nil, fmt.Errorf("tapestats: unterminated listing")
	}
	var devices []string
	rows := 0
	for row := range bytes.SplitSeq(output[:len(output)-1], []byte{'\n'}) {
		rows++
		if rows > agentless.MaxExpandedReads || len(row) > 4096 {
			return nil, fmt.Errorf("tapestats: listing limit exceeded")
		}
		if len(row) == 0 {
			return nil, fmt.Errorf("tapestats: empty listing row")
		}
		// Upstream selects st<N>, excluding non-rewinding and mode aliases
		// so each physical device is exported only once.
		if !bytes.HasPrefix(row, []byte("st")) || len(row) == 2 {
			continue
		}
		valid := true
		for _, digit := range row[2:] {
			if digit < '0' || digit > '9' {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		if (len(devices)+1)*len(tapestatsAttributes) > agentless.MaxExpandedReads {
			return nil, fmt.Errorf("tapestats: expanded read limit exceeded")
		}
		device := string(row)
		for _, previous := range devices {
			if previous == device {
				return nil, fmt.Errorf("tapestats: duplicate device")
			}
		}
		devices = append(devices, device)
	}
	return devices, nil
}
func (c *tapestatsCollector) Expand(_ agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	devices, err := c.devices(in)
	if err != nil {
		return nil, err
	}
	reads := make([]agentless.Read, 0, len(devices)*len(tapestatsAttributes))
	for _, device := range devices {
		for _, spec := range tapestatsAttributes {
			read := tapestatsRead(device, spec.attribute)
			if err := read.Validate(); err != nil {
				return nil, err
			}
			reads = append(reads, read)
		}
	}
	return reads, nil
}
func (c *tapestatsCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	devices, err := c.devices(in)
	if err != nil {
		return err
	}
	var metrics []prometheus.Metric
	for _, device := range devices {
		for i, spec := range tapestatsAttributes {
			read := tapestatsRead(device, spec.attribute)
			if err := read.Validate(); err != nil {
				return err
			}
			result := in[read.ID]
			if result.NotExist && !result.Truncated && !result.TimedOut {
				continue
			}
			output, err := in.Output(read)
			if err != nil {
				return err
			}
			// Bound the entire raw attribute before trimming or converting it.
			if len(output) > 21 {
				return fmt.Errorf("tapestats: numeric attribute too long")
			}
			raw := strings.TrimSpace(string(output))
			value, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return fmt.Errorf("tapestats: invalid numeric attribute %s", spec.attribute)
			}
			metrics = append(metrics, targetMetric(c.descs[i], spec.kind, float64(value)*spec.scale, device))
		}
	}
	for _, metric := range metrics {
		ch <- metric
	}
	return nil
}
