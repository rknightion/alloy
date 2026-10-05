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
	"testing"

	"github.com/grafana/alloy/internal/agentless"
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
	t.Fatal(agentless.ErrNotImplemented)
}
