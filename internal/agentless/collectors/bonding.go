package collectors

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	Register(Registration{Name: "bonding", OS: "linux", DefaultEnabled: true, Factory: newBondingCollector})
}

type bondingCollector struct{ slaves, active *prometheus.Desc }

var _ agentless.Expander = (*bondingCollector)(nil)

func newBondingCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &bondingCollector{
		slaves: prometheus.NewDesc(agentless.Namespace+"_bonding_slaves", "Number of configured slaves per bonding interface.", []string{"master"}, nil),
		active: prometheus.NewDesc(agentless.Namespace+"_bonding_active", "Number of active slaves per bonding interface.", []string{"master"}, nil),
	}, nil
}
func (*bondingCollector) Name() string { return "bonding" }
func (*bondingCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/sys/class/net/bonding_masters"), agentless.CommandRead("ls", "-1", "/sys/class/net")}
}
func bondingRead(device, attribute string) agentless.Read {
	return agentless.FileRead("/sys/class/net/" + device + "/" + attribute)
}
func bondingOutput(in agentless.Input, read agentless.Read) ([]byte, error) {
	if err := read.Validate(); err != nil {
		return nil, err
	}
	result := in[read.ID]
	if result.NotExist && !result.Truncated && !result.TimedOut {
		return nil, nil
	}
	return in.Output(read)
}

// Bound tokens and bytes before retaining names. A whitespace-delimited file
// and an ls listing share the same safe single-component name restrictions.
func bondingNames(output []byte) ([]string, error) {
	var names []string
	rows := 0
	for token := range bytes.FieldsSeq(output) {
		rows++
		if rows > agentless.MaxExpandedReads || len(token) > 4096 {
			return nil, fmt.Errorf("bonding: listing limit exceeded")
		}
		if len(token) == 0 {
			return nil, fmt.Errorf("bonding: empty listing row")
		}
		name := string(token)
		if name == "bonding_masters" || name == "." || strings.Contains(name, "/") || bondingRead(name, "bonding/slaves").Validate() != nil {
			return nil, fmt.Errorf("bonding: invalid interface name")
		}
		for _, previous := range names {
			if previous == name {
				return nil, fmt.Errorf("bonding: duplicate interface")
			}
		}
		names = append(names, name)
	}
	return names, nil
}
func (c *bondingCollector) names(in agentless.Input) ([]string, []string, error) {
	fixed := c.Reads()
	mastersOutput, err := bondingOutput(in, fixed[0])
	if err != nil {
		return nil, nil, err
	}
	// No bonding driver: do not require or retain the interface listing.
	if len(bytes.TrimSpace(mastersOutput)) == 0 {
		return nil, nil, nil
	}
	masters, err := bondingNames(mastersOutput)
	if err != nil {
		return nil, nil, err
	}
	output, err := bondingOutput(in, fixed[1])
	if err != nil {
		return nil, nil, err
	}
	if in[fixed[1].ID].NotExist {
		return nil, nil, nil
	}
	// ls includes the regular bonding_masters control file, not an interface.
	ifaces, err := bondingInterfaces(output, agentless.MaxExpandedReads-len(masters))
	if err != nil {
		return nil, nil, err
	}
	return masters, ifaces, nil
}

func bondingInterfaces(output []byte, budget int) ([]string, error) {
	if len(output) == 0 {
		return nil, nil
	}
	if output[len(output)-1] != '\n' {
		return nil, fmt.Errorf("bonding: unterminated listing")
	}
	var names []string
	rows := 0
	for row := range bytes.SplitSeq(output[:len(output)-1], []byte{'\n'}) {
		rows++
		if rows > agentless.MaxExpandedReads || len(row) > 4096 {
			return nil, fmt.Errorf("bonding: listing limit exceeded")
		}
		if bytes.Equal(row, []byte("bonding_masters")) {
			continue
		}
		parsed, err := bondingNames(row)
		if err != nil || len(parsed) != 1 || !bytes.Equal(row, []byte(parsed[0])) {
			return nil, fmt.Errorf("bonding: invalid listing row")
		}
		for _, previous := range names {
			if previous == parsed[0] {
				return nil, fmt.Errorf("bonding: duplicate interface")
			}
		}
		if len(names) == budget {
			return nil, fmt.Errorf("bonding: expanded read limit exceeded")
		}
		names = append(names, parsed[0])
	}
	return names, nil
}
func (c *bondingCollector) Expand(_ agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	masters, ifaces, err := c.names(in)
	if err != nil {
		return nil, err
	}
	reads := make([]agentless.Read, 0, len(masters)+len(ifaces))
	for _, master := range masters {
		reads = append(reads, bondingRead(master, "bonding/slaves"))
	}
	for _, iface := range ifaces {
		reads = append(reads, bondingRead(iface, "bonding_slave/mii_status"))
	}
	for _, read := range reads {
		if err := read.Validate(); err != nil {
			return nil, err
		}
	}
	return reads, nil
}
func (c *bondingCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	masters, ifaces, err := c.names(in)
	if err != nil {
		return err
	}
	states := make(map[string]bool, len(ifaces))
	for _, iface := range ifaces {
		read := bondingRead(iface, "bonding_slave/mii_status")
		output, err := bondingOutput(in, read)
		if err != nil {
			return err
		}
		if in[read.ID].NotExist {
			continue
		}
		state := bytes.TrimSpace(output)
		if len(state) > 4096 {
			return fmt.Errorf("bonding: status limit exceeded")
		}
		states[iface] = bytes.Equal(state, []byte("up"))
	}
	var metrics []prometheus.Metric
	for _, master := range masters {
		read := bondingRead(master, "bonding/slaves")
		output, err := bondingOutput(in, read)
		if err != nil {
			return err
		}
		if in[read.ID].NotExist {
			continue
		}
		slaves, err := bondingNames(output)
		if err != nil {
			return err
		}
		active, complete := 0, true
		for _, slave := range slaves {
			up, exists := states[slave]
			if !exists {
				complete = false
			}
			if up {
				active++
			}
		}
		if !complete {
			continue
		}
		metrics = append(metrics, targetMetric(c.slaves, prometheus.GaugeValue, float64(len(slaves)), master), targetMetric(c.active, prometheus.GaugeValue, float64(active), master))
	}
	for _, metric := range metrics {
		ch <- metric
	}
	return nil
}
