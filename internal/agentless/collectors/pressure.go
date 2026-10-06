package collectors

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
)

func init() {
	Register(Registration{Name: "pressure", OS: "linux", DefaultEnabled: true, Factory: newPressureCollector})
}

type pressureCollector struct{}

func newPressureCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &pressureCollector{}, nil
}

// Name implements agentless.Collector.
func (c *pressureCollector) Name() string { return "pressure" }

// Reads implements agentless.Collector.
func (c *pressureCollector) Reads() []agentless.Read {
	return []agentless.Read{
		agentless.FileRead("/proc/pressure/cpu"),
		agentless.FileRead("/proc/pressure/memory"),
		agentless.FileRead("/proc/pressure/io"),
		agentless.FileRead("/proc/pressure/irq"),
	}
}

// Update implements agentless.Collector. Only node_exporter's default five
// families are emitted; CPU full and IRQ statistics are validated but not exported.
func (c *pressureCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	var metrics [5]prometheus.Metric
	count := 0
	for i, read := range c.Reads() {
		res, ok := in[read.ID]
		if ok && res.NotExist && !res.TimedOut && !res.Truncated {
			continue
		}
		output, err := in.Output(read)
		if err != nil {
			return err
		}
		totals, seen, err := parsePressure(output)
		if err != nil {
			return fmt.Errorf("pressure %s: %w", read.Path, err)
		}
		if (i < 3 && !seen[0]) || (i > 0 && !seen[1]) {
			return fmt.Errorf("pressure %s: missing required row", read.Path)
		}
		var names, helps []string
		switch i {
		case 0:
			names = []string{"cpu_waiting_seconds_total"}
			helps = []string{"Total time in seconds that processes have waited for CPU time"}
		case 1:
			names = []string{"memory_waiting_seconds_total", "memory_stalled_seconds_total"}
			helps = []string{"Total time in seconds that processes have waited for memory", "Total time in seconds no process could make progress due to memory congestion"}
		case 2:
			names = []string{"io_waiting_seconds_total", "io_stalled_seconds_total"}
			helps = []string{"Total time in seconds that processes have waited due to IO congestion", "Total time in seconds no process could make progress due to IO congestion"}
		}
		for j, name := range names {
			desc := prometheus.NewDesc(prometheus.BuildFQName(agentless.Namespace, "pressure", name), helps[j], nil, nil)
			metrics[count] = targetMetric(desc, prometheus.CounterValue, float64(totals[j])/1000.0/1000.0)
			count++
		}
	}
	// Validate all four reads before sending; hostile data retains at most five metrics.
	for _, metric := range metrics[:count] {
		ch <- metric
	}
	return nil
}

// parsePressure retains only the two fixed PSI row totals. The bounded scanner
// and duplicate-row check prevent arbitrary remote output from growing state.
func parsePressure(output []byte) ([2]uint64, [2]bool, error) {
	var totals [2]uint64
	var seen [2]bool
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 1024), 4096)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 5 {
			return totals, seen, fmt.Errorf("malformed PSI row")
		}
		row := 0
		switch fields[0] {
		case "some":
		case "full":
			row = 1
		default:
			return totals, seen, fmt.Errorf("unknown PSI row")
		}
		if seen[row] {
			return totals, seen, fmt.Errorf("duplicate PSI row")
		}
		seen[row] = true
		for i, key := range [...]string{"avg10", "avg60", "avg300", "total"} {
			value, ok := strings.CutPrefix(fields[i+1], key+"=")
			if !ok {
				return totals, seen, fmt.Errorf("missing PSI field %s", key)
			}
			if key == "total" {
				total, err := strconv.ParseUint(value, 10, 64)
				if err != nil {
					return totals, seen, fmt.Errorf("invalid PSI total: %w", err)
				}
				totals[row] = total
			} else {
				avg, err := strconv.ParseFloat(value, 64)
				if err != nil || math.IsNaN(avg) || math.IsInf(avg, 0) || avg < 0 {
					return totals, seen, fmt.Errorf("invalid PSI average %s", key)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return totals, seen, fmt.Errorf("scan PSI: %w", err)
	}
	return totals, seen, nil
}
