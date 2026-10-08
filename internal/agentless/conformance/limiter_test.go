package conformance_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

type budgetCollector struct {
	second, third []agentless.Read
}

func (budgetCollector) Name() string            { return "budget" }
func (budgetCollector) Reads() []agentless.Read { return nil }
func (c budgetCollector) Expand(agentless.Target, agentless.Input) ([]agentless.Read, error) {
	return c.second, nil
}
func (c budgetCollector) ExpandDeep(agentless.Target, agentless.Input) ([]agentless.Read, error) {
	return c.third, nil
}
func (budgetCollector) Update(_ agentless.Target, _ agentless.Input, ch chan<- prometheus.Metric) error {
	ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("node_test_budget", "Budget.", nil, nil), prometheus.GaugeValue, 1)
	return nil
}

type limitedBudgetCollector struct {
	budgetCollector
	limit int
}

func (c limitedBudgetCollector) DeepListingLimit() int { return c.limit }

func TestCheckDeepListingLimit(t *testing.T) {
	for _, tc := range []struct {
		name     string
		limit, n int
		declared bool
		failure  string
	}{
		{"default64", 64, 64, false, ""},
		{"default65", 64, 65, false, "deep listing limit exceeded"},
		{"declared512", 512, 512, true, ""},
		{"declared513reads", 512, 513, true, "deep listing limit exceeded"},
		{"declared32", 32, 33, true, "deep listing limit exceeded"},
		{"zero", 0, 0, true, "outside [1, 512]"},
		{"negative", -1, 0, true, "outside [1, 512]"},
		{"aboveCeiling", 513, 0, true, "outside [1, 512]"},
	} {
		for _, phase := range []string{"listings", "earlyLinks", "links", "combined"} {
			t.Run(tc.name+"/"+phase, func(t *testing.T) {
				if os.Getenv("CONFORMANCE_LIMIT_CASE") != t.Name() {
					ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCheckDeepListingLimit$/^"+tc.name+"$/^"+phase+"$", "-test.v")
					cmd.Env = append(os.Environ(), "CONFORMANCE_LIMIT_CASE="+t.Name())
					out, err := cmd.CombinedOutput()
					require.NoError(t, ctx.Err(), "subprocess timed out: %s", out)
					if tc.failure == "" {
						require.NoError(t, err, "%s", out)
					} else {
						require.Error(t, err, "Check unexpectedly accepted the collector: %s", out)
						require.Contains(t, string(out), "--- FAIL: TestCheckDeepListingLimit")
						require.Contains(t, string(out), "conformance: deep listing limit")
						require.Contains(t, string(out), tc.failure)
					}
					return
				}
				root := t.TempDir()
				require.NoError(t, os.Mkdir(filepath.Join(root, "sys"), 0o700))
				base := budgetCollector{}
				for i := range tc.n {
					path := fmt.Sprintf("/sys/device%d", i)
					read := agentless.CommandRead("ls", "-1", path)
					if phase == "earlyLinks" || phase == "links" || phase == "combined" && i >= tc.n/2 {
						require.NoError(t, os.Symlink("/sys/resolved", filepath.Join(root, path)))
						read = agentless.CommandRead("readlink", "-f", path)
					} else {
						require.NoError(t, os.Mkdir(filepath.Join(root, path), 0o700))
					}
					if phase == "links" || phase == "combined" && i >= tc.n/2 {
						base.third = append(base.third, read)
					} else {
						base.second = append(base.second, read)
					}
				}
				expected := filepath.Join(root, "expected")
				require.NoError(t, os.WriteFile(expected, []byte("# HELP node_test_budget Budget.\n# TYPE node_test_budget gauge\nnode_test_budget 1\n"), 0o600))
				var collector agentless.Collector = base
				if tc.declared {
					collector = limitedBudgetCollector{base, tc.limit}
				}
				conformance.Check(t, conformance.Case{Collector: collector, Root: root, Expected: expected, Families: []string{"node_test_budget"}})
			})
		}
	}
}
