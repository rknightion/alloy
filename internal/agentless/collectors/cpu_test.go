package collectors

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestCPUConformance(t *testing.T) {
	c, err := newCPUCollector(Configs{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	conformance.Check(t, conformance.Case{Collector: c, Families: []string{"node_cpu_seconds_total", "node_cpu_guest_seconds_total"}})
}

// cpuSnapshot exercises emitted metrics rather than inspecting cached state.
func cpuSnapshot(t *testing.T, c agentless.Collector, target agentless.Target, text string) map[string]float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 100)
	if err := c.Update(target, statInput(text), ch); err != nil {
		t.Fatal(err)
	}
	close(ch)
	values := make(map[string]float64)
	for metric := range ch {
		var wire dto.Metric
		if err := metric.Write(&wire); err != nil {
			t.Fatal(err)
		}
		var cpu, mode string
		for _, label := range wire.Label {
			switch label.GetName() {
			case "cpu":
				cpu = label.GetValue()
			case "mode":
				mode = label.GetValue()
			}
		}
		family := "cpu"
		if metric.Desc() == cpuGuestSecondsDesc {
			family = "guest"
		}
		values[family+"/"+cpu+"/"+mode] = wire.GetCounter().GetValue()
	}
	return values
}

func TestCPUCounterGuards(t *testing.T) {
	c, _ := newCPUCollector(Configs{}, nil)
	target := agentless.Target{Address: "host", Auth: "one"}
	initial := "cpu0 1000 2000 3000 1000 500 600 700 800 900 1000\ncpu1 100 200 300 400 500 600 700 800 900 1000\n"
	cpuSnapshot(t, c, target, initial)
	// Regress every counter; idle regresses only 2.99 seconds, so retain them.
	got := cpuSnapshot(t, c, target, "cpu0 1 2 3 701 5 6 7 8 9 10\ncpu2 1 2 3 4\n")
	for key, want := range map[string]float64{"cpu/0/user": 10, "cpu/0/nice": 20, "cpu/0/system": 30, "cpu/0/idle": 10, "cpu/0/iowait": 5, "cpu/0/irq": 6, "cpu/0/softirq": 7, "cpu/0/steal": 8, "guest/0/user": 9, "guest/0/nice": 10, "cpu/2/user": 0.01, "cpu/2/steal": 0} {
		if got[key] != want {
			t.Errorf("%s = %g, want %g", key, got[key], want)
		}
	}
	if len(got) != 20 {
		t.Fatalf("offline CPU still emitted: %v", got)
	}
	// Exactly three seconds resets every counter.
	got = cpuSnapshot(t, c, target, "cpu0 1 2 3 700 5 6 7 8 9 10\n")
	if got["cpu/0/user"] != 0.01 || got["cpu/0/idle"] != 7 || got["guest/0/user"] != 0.09 {
		t.Fatalf("hotplug reset: %v", got)
	}
	// Removing then re-adding a CPU must not resurrect old counters.
	cpuSnapshot(t, c, target, "cpu2 1 2 3 4\n")
	got = cpuSnapshot(t, c, target, "cpu0 1 2 3 699\n")
	if got["cpu/0/idle"] != 6.99 {
		t.Fatalf("offline state retained: %v", got)
	}
}

func TestCPUTargetIsolationAndConcurrency(t *testing.T) {
	c, _ := newCPUCollector(Configs{}, nil)
	cpuSnapshot(t, c, agentless.Target{Address: "same", Auth: "a"}, "cpu0 9000 0 0 1000\n")
	got := cpuSnapshot(t, c, agentless.Target{Address: "same", Auth: "b"}, "cpu0 1 0 0 1000\n")
	if got["cpu/0/user"] != 0.01 {
		t.Fatalf("auth targets share state: %v", got)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			target := agentless.Target{Address: fmt.Sprintf("host-%d", i%5)}
			for j := 0; j < 10; j++ {
				cpuSnapshot(t, c, target, "cpu0 100 200 300 400 500 600 700 800 900 1000\n")
			}
		}(i)
	}
	wg.Wait()
}

func TestCPUGuestAndReadFailures(t *testing.T) {
	c, _ := newCPUCollector(Configs{}, nil)
	target := agentless.Target{Address: "host"}
	got := cpuSnapshot(t, c, target, "cpu 999 999 999 999\ncpu0 100 200 300 400 500 600 700 800 90 80\n")
	if len(got) != 10 || got["cpu/0/user"] != 1 || got["cpu/0/nice"] != 2 || got["guest/0/user"] != 0.9 || got["guest/0/nice"] != 0.8 {
		t.Fatalf("guest semantics: %v", got)
	}
	if err := c.Update(target, statInput("cpu0 1000 2000 3000 4000\nctxt bad\n"), make(chan prometheus.Metric, 100)); err == nil {
		t.Fatal("malformed scrape accepted")
	}
	got = cpuSnapshot(t, c, target, "cpu0 100 200 300 400\n")
	if got["cpu/0/user"] != 1 {
		t.Fatalf("failed scrape mutated state: %v", got)
	}
}

func TestCPUStatScraperSharedRead(t *testing.T) {
	cpu, _ := newCPUCollector(Configs{}, nil)
	stat, _ := newStatCollector(Configs{}, nil)
	read := agentless.FileRead("/proc/stat")
	runner := &agentlesstest.FakeRunner{Results: map[string]agentless.Result{read.ID: {Read: read, Output: []byte("cpu0 100 200 300 400\nintr 7\nctxt 8\nprocesses 9\nbtime 10\nprocs_running 1\nprocs_blocked 2\n")}}}
	scraper, err := agentless.NewScraper(runner, []agentless.Collector{cpu, stat}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(scraper.Reads()) != 1 {
		t.Fatalf("reads not deduplicated: %v", scraper.Reads())
	}
	collector, err := scraper.Scrape(context.Background(), agentless.Target{Address: "host"})
	if err != nil {
		t.Fatal(err)
	}
	registry := prometheus.NewRegistry()
	registry.MustRegister(collector)
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	successes := 0
	for _, family := range families {
		if family.GetName() == "node_scrape_collector_success" {
			for _, metric := range family.Metric {
				if metric.GetGauge().GetValue() != 1 {
					t.Fatalf("failed collector: %v", metric)
				}
				successes++
			}
		}
	}
	if successes != 2 || runner.Calls() != 1 {
		t.Fatalf("collector successes = %d, batches = %d", successes, runner.Calls())
	}
}
