package collectors

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
)

func init() {
	Register(Registration{Name: "uname", OS: "linux", DefaultEnabled: true, Factory: newUnameCollector})
}

type unameCollector struct{}

func newUnameCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &unameCollector{}, nil
}

// Name implements agentless.Collector.
func (c *unameCollector) Name() string { return "uname" }

// Reads implements agentless.Collector.
func (c *unameCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.CommandRead("uname", "-s"), agentless.CommandRead("uname", "-n"), agentless.CommandRead("uname", "-r"), agentless.CommandRead("uname", "-v"), agentless.CommandRead("uname", "-m"), agentless.FileRead("/proc/sys/kernel/domainname")}
}

// Update implements agentless.Collector.
func (c *unameCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	values := make([]string, 0, 6)
	for _, read := range c.Reads() {
		result, ok := in[read.ID]
		if ok && result.NotExist {
			return fmt.Errorf("uname: read %q does not exist", read.ID)
		}
		output, err := in.Output(read)
		if err != nil {
			return err
		}
		// Preserve spaces in the kernel version, stripping only the command's
		// final newline. domainname is the kernel NIS domain, not a DNS suffix.
		values = append(values, strings.TrimSuffix(string(output), "\n"))
	}
	ch <- targetMetric(unameInfoDesc, prometheus.GaugeValue, 1, values...)
	return nil
}

var unameInfoDesc = prometheus.NewDesc(
	prometheus.BuildFQName(agentless.Namespace, "uname", "info"),
	"Labeled system information as provided by the uname system call.",
	[]string{"sysname", "nodename", "release", "version", "machine", "domainname"}, nil,
)
