// Package conformance proves that a collector emits the same metric families,
// labels and values as node_exporter for the same input. It feeds
// node_exporter's own fixture files through a collector and compares the result
// with node_exporter's expected exposition output for the families the
// collector owns.
//
// node_exporter's e2e output does not cover every collector: netdev values come
// from netlink on its test host, and filesystem and uname are disabled there.
// Those collectors check against goldens they author themselves from real
// target output, which is a weaker proof and is labelled as such. Check calls
// Collector.Update directly rather than through a Scraper, so the
// node_scrape_collector_* families never appear in the comparison.
package conformance

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// Case describes one conformance check.
type Case struct {
	// Collector is the collector under test.
	Collector agentless.Collector
	// Families lists the metric family names the collector owns. The check
	// fails if the collector emits a family outside this list, or if the
	// expected output holds a listed family the collector does not emit.
	// Families node_exporter derives from sources this package cannot read
	// (/sys, cpuinfo, netlink) are left out.
	Families []string
	// Root is the directory standing in for the target's filesystem root.
	// Empty means the vendored node_exporter fixtures, where /proc/stat is
	// answered from proc/stat.
	Root string
	// Commands maps a command Read.ID to a file holding that command's
	// output. node_exporter has no fixtures for command output, so collectors
	// that run commands supply their own.
	Commands map[string]string
	// Expected is the path of the expected exposition output. Empty means
	// the vendored node_exporter e2e output.
	Expected string
}

// Check runs c and fails t on any difference.
func Check(t testing.TB, c Case) {
	t.Helper()
	if c.Collector == nil || len(c.Families) == 0 {
		t.Fatal("conformance: collector and owned families are required")
	}
	owned := make(map[string]bool, len(c.Families))
	for _, name := range c.Families {
		if name == "" || owned[name] {
			t.Fatalf("conformance: empty or duplicate family %q", name)
		}
		owned[name] = true
	}
	// Resolve defaults relative to this package, not the calling collector's
	// working directory. Explicit paths remain relative to the caller.
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("conformance: cannot locate vendored fixtures")
	}
	fixtures := filepath.Join(filepath.Dir(source), "testdata", "node_exporter")
	if c.Root == "" {
		c.Root = fixtures
	}
	if c.Expected == "" {
		c.Expected = filepath.Join(fixtures, "e2e-output.txt")
	}
	expected, err := os.ReadFile(c.Expected)
	if err != nil {
		t.Fatalf("conformance: read expected output: %v", err)
	}
	parser := expfmt.NewTextParser(model.LegacyValidation)
	families, err := parser.TextToMetricFamilies(bytes.NewReader(expected))
	if err != nil {
		t.Fatalf("conformance: parse expected output: %v", err)
	}
	for name := range owned {
		if families[name] == nil || len(families[name].Metric) == 0 {
			t.Fatalf("conformance: expected output has no owned family %q", name)
		}
	}
	reads := c.Collector.Reads()
	runner, err := agentlesstest.FromFS(c.Root, c.Commands, reads)
	if err != nil {
		t.Fatalf("conformance: read fixtures: %v", err)
	}
	target := agentless.Target{Address: "conformance"}
	results, err := runner.Run(context.Background(), target, reads)
	if err != nil {
		t.Fatalf("conformance: fixture runner: %v", err)
	}
	in := make(agentless.Input, len(results))
	for _, result := range results {
		in[result.Read.ID] = result
	}
	registry := prometheus.NewRegistry()
	registry.MustRegister(updateCollector{collector: c.Collector, target: target, input: in})
	actual, err := registry.Gather()
	if err != nil {
		t.Fatalf("conformance: Update or metric gathering failed: %v", err)
	}
	for _, family := range actual {
		if !owned[family.GetName()] {
			t.Fatalf("conformance: collector emitted unowned family %q", family.GetName())
		}
	}
	// Reuse the gathered snapshot so stateful Update runs exactly once.
	gatherer := prometheus.GathererFunc(func() ([]*dto.MetricFamily, error) { return actual, nil })
	if err := testutil.GatherAndCompare(gatherer, bytes.NewReader(expected), c.Families...); err != nil {
		t.Fatalf("conformance: metrics differ: %v", err)
	}
}

// updateCollector is unchecked because the oracle validates the descriptors.
// Collect calls Update directly; no Scraper or scrape self-metrics are involved.
type updateCollector struct {
	collector agentless.Collector
	target    agentless.Target
	input     agentless.Input
}

func (updateCollector) Describe(chan<- *prometheus.Desc) {}

func (c updateCollector) Collect(ch chan<- prometheus.Metric) {
	if err := c.collector.Update(c.target, c.input, ch); err != nil {
		ch <- prometheus.NewInvalidMetric(prometheus.NewDesc("conformance_update_error", "Update failed.", nil, nil), fmt.Errorf("Update: %w", err))
	}
}
