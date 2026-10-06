package collectors

import (
	"fmt"
	"strings"
	"testing"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestStatConformance(t *testing.T) {
	c, err := newStatCollector(Configs{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	conformance.Check(t, conformance.Case{Collector: c, Families: []string{"node_intr_total", "node_context_switches_total", "node_forks_total", "node_boot_time_seconds", "node_procs_running", "node_procs_blocked"}})
}

func statInput(text string) agentless.Input {
	read := agentless.FileRead("/proc/stat")
	return agentless.Input{read.ID: {Read: read, Output: []byte(text)}}
}

func TestProcStatParsing(t *testing.T) {
	t.Run("long interrupt line and unknown fields", func(t *testing.T) {
		stats, err := readProcStat(statInput("\nfuture value\nintr 42" + strings.Repeat(" 1", 40000) + "\ncpu0 1 2 3 4\n"))
		if err != nil {
			t.Fatal(err)
		}
		if stats.values["intr"] != 42 || stats.cpus[0][0] != 0.01 || stats.cpus[0][9] != 0 {
			t.Fatalf("parsed: %+v", stats)
		}
	})
	for _, text := range []string{"cpu0 bad\n", "cpuBAD 1 2 3 4\n", "cpu-1 1 2 3 4\n", "cpu0 -1 2 3 4\n", "ctxt bad\n", "btime -1\n", "intr 1 bad\n", "softirq 1 2\n", "softirq 1 2 3 4 5 6 7 8 9 10 bad\n", "procs_running\n", "processes 18446744073709551616\n", "intr 1" + strings.Repeat(" 0", 600000)} {
		t.Run(text[:min(len(text), 40)], func(t *testing.T) {
			if _, err := readProcStat(statInput(text)); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
}

func TestCollectorsRejectFailedReads(t *testing.T) {
	cpu, _ := newCPUCollector(Configs{}, nil)
	stat, _ := newStatCollector(Configs{}, nil)
	read := agentless.FileRead("/proc/stat")
	for _, c := range []agentless.Collector{cpu, stat} {
		for name, in := range map[string]agentless.Input{
			"missing":   {},
			"exit":      {read.ID: {ExitStatus: 1}},
			"not exist": {read.ID: {ExitStatus: 1, NotExist: true}},
			"truncated": {read.ID: {Truncated: true}},
			"timed out": {read.ID: {TimedOut: true}},
			"malformed": statInput("ctxt invalid\n"),
		} {
			t.Run(c.Name()+"/"+name, func(t *testing.T) {
				ch := make(chan prometheus.Metric, 100)
				if err := c.Update(agentless.Target{}, in, ch); err == nil {
					t.Fatal("failed read accepted")
				}
				if len(ch) != 0 {
					t.Fatal("metrics emitted before parse succeeded")
				}
			})
		}
	}
}

func TestProcStatCPULimits(t *testing.T) {
	var boundary strings.Builder
	for i := 0; i < 8192; i++ {
		fmt.Fprintf(&boundary, "cpu%d 1 2 3 4\n", i)
	}
	for name, text := range map[string]string{
		"line boundary": boundary.String(),
		"ID boundary":   "cpu65535 1 2 3 4\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readProcStat(statInput(text)); err != nil {
				t.Fatalf("valid boundary rejected: %v", err)
			}
		})
	}
	cpu, _ := newCPUCollector(Configs{}, nil)
	stat, _ := newStatCollector(Configs{}, nil)
	for _, c := range []agentless.Collector{cpu, stat} {
		for name, text := range map[string]string{
			"8193 lines":      boundary.String() + "cpu8192 1 2 3 4\n",
			"duplicate lines": strings.Repeat("cpu0 1 2 3 4\n", 8193),
			"aggregate lines": strings.Repeat("cpu 1 2 3 4\n", 8193),
			"ID 65536":        "cpu65536 1 2 3 4\n",
		} {
			t.Run(c.Name()+"/"+name, func(t *testing.T) {
				ch := make(chan prometheus.Metric, 81930)
				if err := c.Update(agentless.Target{}, statInput(text), ch); err == nil {
					t.Error("excess CPU input accepted")
				}
				if len(ch) != 0 {
					t.Error("metrics emitted for excess CPU input")
				}
			})
		}
	}
}

func TestStatMetricTypesAndValues(t *testing.T) {
	c, _ := newStatCollector(Configs{}, nil)
	ch := make(chan prometheus.Metric, 10)
	if err := c.Update(agentless.Target{}, statInput("intr 7 1 2\nctxt 8\nprocesses 9\nbtime 10\nprocs_running 11\nprocs_blocked 12\n"), ch); err != nil {
		t.Fatal(err)
	}
	close(ch)
	i := 0
	for metric := range ch {
		var wire dto.Metric
		if err := metric.Write(&wire); err != nil {
			t.Fatal(err)
		}
		want := float64(7 + i)
		if i < 3 {
			if wire.Counter == nil || wire.GetCounter().GetValue() != want {
				t.Fatalf("counter %d: %v", i, &wire)
			}
		} else if wire.Gauge == nil || wire.GetGauge().GetValue() != want {
			t.Fatalf("gauge %d: %v", i, &wire)
		}
		i++
	}
	if i != 6 {
		t.Fatalf("metrics = %d", i)
	}
}
