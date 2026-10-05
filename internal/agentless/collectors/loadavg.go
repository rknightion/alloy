package collectors

import (
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
)

func init() {
	Register(Registration{Name: "loadavg", OS: "linux", DefaultEnabled: true, Factory: newLoadavgCollector})
}

type loadavgCollector struct{}

func newLoadavgCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &loadavgCollector{}, nil
}

// Name implements agentless.Collector.
func (c *loadavgCollector) Name() string { return "loadavg" }

// Reads implements agentless.Collector.
func (c *loadavgCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/loadavg")}
}

// Update implements agentless.Collector.
func (c *loadavgCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	output, err := in.Output(agentless.FileRead("/proc/loadavg"))
	if err != nil {
		return err
	}
	fields := strings.Fields(string(output))
	if len(fields) < 3 {
		return fmt.Errorf("loadavg: expected at least three fields, got %d", len(fields))
	}
	var loads [3]float64
	for i := range loads {
		value, err := strconv.ParseFloat(fields[i], 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return fmt.Errorf("loadavg: invalid load value %q", fields[i])
		}
		loads[i] = value
	}
	for i, minutes := range []string{"1", "5", "15"} {
		desc := prometheus.NewDesc(agentless.Namespace+"_load"+minutes, minutes+"m load average.", nil, nil)
		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, loads[i])
	}
	return nil
}
