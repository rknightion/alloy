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
	Register(Registration{Name: "fibrechannel", OS: "linux", DefaultEnabled: true, Factory: newFibrechannelCollector})
}

// Fixed attributes from the pinned node_exporter fibrechannel collector and
// procfs sysfs parser. node_name is read upstream but not exported.
var fibrechannelStrings = [...]string{"speed", "port_state", "port_type", "port_id", "port_name", "fabric_name", "symbolic_name", "supported_classes", "supported_speeds", "dev_loss_tmo", "node_name"}
var fibrechannelCounters = [...]struct{ attribute, family, help string }{
	{"dumped_frames", "dumped_frames_total", "Number of dumped frames"},
	{"error_frames", "error_frames_total", "Number of errors in frames"},
	{"invalid_crc_count", "invalid_crc_total", "Invalid Cyclic Redundancy Check count"},
	{"rx_frames", "rx_frames_total", "Number of frames received"},
	{"rx_words", "rx_words_total", "Number of words received by host port"},
	{"tx_frames", "tx_frames_total", "Number of frames transmitted by host port"},
	{"tx_words", "tx_words_total", "Number of words transmitted by host port"},
	{"seconds_since_last_reset", "seconds_since_last_reset_total", "Number of seconds since last host port reset"},
	{"invalid_tx_word_count", "invalid_tx_words_total", "Number of invalid words transmitted by host port"},
	{"link_failure_count", "link_failure_total", "Number of times the host port link has failed"},
	{"loss_of_sync_count", "loss_of_sync_total", "Number of failures on either bit or transmission word boundaries"},
	{"loss_of_signal_count", "loss_of_signal_total", "Number of times signal has been lost"},
	{"nos_count", "nos_total", "Number Not_Operational Primitive Sequence received by host port"},
	{"fcp_packet_aborts", "fcp_packet_aborts_total", "Number of aborted packets"},
}

const fibrechannelAttributes = len(fibrechannelStrings) + len(fibrechannelCounters)

type fibrechannelCollector struct {
	info     *prometheus.Desc
	counters [len(fibrechannelCounters)]*prometheus.Desc
}

var _ agentless.Expander = (*fibrechannelCollector)(nil)

func newFibrechannelCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	c := &fibrechannelCollector{info: prometheus.NewDesc(agentless.Namespace+"_fibrechannel_info", "Non-numeric data from /sys/class/fc_host/<host>, value is always 1.", append([]string{"fc_host"}, fibrechannelStrings[:len(fibrechannelStrings)-1]...), nil)}
	for i, spec := range fibrechannelCounters {
		c.counters[i] = prometheus.NewDesc(agentless.Namespace+"_fibrechannel_"+spec.family, spec.help, []string{"fc_host"}, nil)
	}
	return c, nil
}

func (*fibrechannelCollector) Name() string { return "fibrechannel" }
func (*fibrechannelCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.CommandRead("ls", "-1", "/sys/class/fc_host")}
}
func fibrechannelRead(host, attribute string) agentless.Read {
	return agentless.FileRead("/sys/class/fc_host/" + host + "/" + attribute)
}

// Bound every row before retaining its name, including invalid names. Each
// host requires 25 reads: 40 hosts fit (1000 reads), 41 reject the entire
// expansion. Labels and names are limited to 4096 bytes. At most 600 series
// can be emitted, well below the existing per-collector output cap.
func (c *fibrechannelCollector) hosts(in agentless.Input) ([]string, error) {
	read := c.Reads()[0]
	result := in[read.ID]
	if result.NotExist && !result.TimedOut && !result.Truncated {
		return nil, nil
	}
	output, err := in.Output(read)
	if err != nil || len(output) == 0 {
		return nil, err
	}
	if output[len(output)-1] != '\n' {
		return nil, fmt.Errorf("fibrechannel: unterminated listing")
	}
	var hosts []string
	rows := 0
	for row := range bytes.SplitSeq(output[:len(output)-1], []byte{'\n'}) {
		rows++
		if rows > agentless.MaxExpandedReads || len(row) > 4096 {
			return nil, fmt.Errorf("fibrechannel: listing limit exceeded")
		}
		if len(row) == 0 {
			return nil, fmt.Errorf("fibrechannel: empty listing row")
		}
		host := string(row)
		if strings.Contains(host, "/") || host == "." || fibrechannelRead(host, "speed").Validate() != nil {
			continue
		}
		for _, previous := range hosts {
			if previous == host {
				return nil, fmt.Errorf("fibrechannel: duplicate host")
			}
		}
		if (len(hosts)+1)*fibrechannelAttributes > agentless.MaxExpandedReads {
			return nil, fmt.Errorf("fibrechannel: expanded read limit exceeded")
		}
		hosts = append(hosts, host)
	}
	return hosts, nil
}

func (c *fibrechannelCollector) Expand(_ agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	hosts, err := c.hosts(in)
	if err != nil {
		return nil, err
	}
	reads := make([]agentless.Read, 0, len(hosts)*fibrechannelAttributes)
	for _, host := range hosts {
		for _, attribute := range fibrechannelStrings {
			read := fibrechannelRead(host, attribute)
			if err := read.Validate(); err != nil {
				return nil, err
			}
			reads = append(reads, read)
		}
		for _, spec := range fibrechannelCounters {
			read := fibrechannelRead(host, "statistics/"+spec.attribute)
			if err := read.Validate(); err != nil {
				return nil, err
			}
			reads = append(reads, read)
		}
	}
	return reads, nil
}

// Missing driver attributes are optional. All other transport failures must
// fail this collector, including missing results and missing+timeout/truncated.
func fibrechannelOutput(in agentless.Input, read agentless.Read) ([]byte, bool, error) {
	if err := read.Validate(); err != nil {
		return nil, false, err
	}
	result := in[read.ID]
	if result.NotExist && !result.TimedOut && !result.Truncated {
		return nil, false, nil
	}
	output, err := in.Output(read)
	return output, true, err
}

func (c *fibrechannelCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	hosts, err := c.hosts(in)
	if err != nil {
		return err
	}
	// Publish only after every attribute is parsed, so malformed later hosts
	// cannot leak partial series from an otherwise failed collector.
	metrics := make([]prometheus.Metric, 0, len(hosts)*(len(fibrechannelCounters)+1))
	for _, host := range hosts {
		labels := make([]string, len(fibrechannelStrings))
		labels[0] = host
		for i, attribute := range fibrechannelStrings {
			output, present, err := fibrechannelOutput(in, fibrechannelRead(host, attribute))
			if err != nil {
				return err
			}
			if !present {
				continue
			}
			if len(output) > 4097 {
				return fmt.Errorf("fibrechannel: attribute too long")
			}
			value := bytes.TrimSpace(output)
			if len(value) > 4096 || !utf8.Valid(value) {
				return fmt.Errorf("fibrechannel: invalid attribute label")
			}
			if attribute == "port_id" || attribute == "port_name" || attribute == "fabric_name" || attribute == "node_name" {
				// Match procfs: remove the first two bytes when present.
				if len(value) > 2 {
					value = value[2:]
				}
			}
			if i < len(fibrechannelStrings)-1 {
				labels[i+1] = string(value)
			}
		}
		metrics = append(metrics, targetMetric(c.info, prometheus.GaugeValue, 1, labels...))
		for i, spec := range fibrechannelCounters {
			output, present, err := fibrechannelOutput(in, fibrechannelRead(host, "statistics/"+spec.attribute))
			if err != nil {
				return err
			}
			if !present {
				continue
			}
			if len(output) > 25 {
				return fmt.Errorf("fibrechannel: numeric attribute too long")
			}
			value, err := strconv.ParseUint(string(bytes.TrimSpace(output)), 0, 64)
			if err != nil {
				return fmt.Errorf("fibrechannel: invalid numeric attribute %s", spec.attribute)
			}
			// Firmware uses maxUint64 to mark unimplemented counters.
			if value != ^uint64(0) {
				metrics = append(metrics, targetMetric(c.counters[i], prometheus.CounterValue, float64(value), host))
			}
		}
	}
	for _, metric := range metrics {
		ch <- metric
	}
	return nil
}
