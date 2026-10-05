package ssh

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/collectors"
	"github.com/grafana/alloy/internal/component/discovery"
	"github.com/stretchr/testify/require"
)

type runnerFunc func(context.Context, agentless.Target, []agentless.Read) ([]agentless.Result, error)

func (f runnerFunc) Run(ctx context.Context, t agentless.Target, r []agentless.Read) ([]agentless.Result, error) {
	return f(ctx, t, r)
}

func TestHandlerContract(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, tc := range []struct {
		name, target, header string
		want                 int
		transportError       bool
		budget               time.Duration
	}{
		{name: "allowed", target: "host", want: 200, budget: time.Second},
		{name: "unknown", target: "other", want: 400},
		{name: "missing", want: 400},
		{name: "duplicate", target: "host&target=other", want: 400},
		{name: "transport", target: "host", want: 503, transportError: true, budget: time.Second},
		{name: "header", target: "host", header: "0.8", want: 200, budget: 300 * time.Millisecond},
		{name: "capped", target: "host", header: "100", want: 200, budget: time.Second},
		{name: "invalid", target: "host", header: "NaN", want: 400},
		{name: "exhausted", target: "host", header: "0.4", want: 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			run := runnerFunc(func(ctx context.Context, target agentless.Target, reads []agentless.Read) ([]agentless.Result, error) {
				calls++
				require.Equal(t, "host", target.Address)
				deadline, ok := ctx.Deadline()
				require.True(t, ok)
				require.InDelta(t, tc.budget.Seconds(), time.Until(deadline).Seconds(), 0.08)
				if tc.transportError {
					return nil, errors.New("sensitive transport detail")
				}
				return []agentless.Result{{Read: reads[0], Output: []byte("1.5 2.0 3.0 1/42 100\n")}}, nil
			})
			cs, err := collectors.Build([]string{"loadavg"}, collectors.DefaultConfigs(), logger)
			require.NoError(t, err)
			scraper, err := agentless.NewScraper(run, cs, logger)
			require.NoError(t, err)
			c := &Component{scraper: scraper, allowed: map[string]agentless.Target{"host": {Address: "host"}}, timeout: time.Second}
			req := httptest.NewRequest("GET", "/metrics?target="+tc.target, nil)
			req.Header.Set("X-Prometheus-Scrape-Timeout-Seconds", tc.header)
			w := httptest.NewRecorder()
			c.Handler().ServeHTTP(w, req)
			require.Equal(t, tc.want, w.Code)
			require.NotContains(t, w.Body.String(), "sensitive")
			if tc.want == 200 {
				require.Contains(t, w.Body.String(), "node_load1 1.5")
				require.Contains(t, w.Body.String(), "node_scrape_collector_success{collector=\"loadavg\"} 1")
			}
			if tc.want == 400 {
				require.Zero(t, calls)
			} else {
				require.Equal(t, 1, calls)
			}
		})
	}
}

func TestTargets(t *testing.T) {
	base := discovery.NewTargetFromMap(map[string]string{"__address__": "alloy.internal:12345", "__metrics_path__": "/component/metrics", "job": "integrations/ssh"})
	a := Arguments{TargetsList: []discovery.Target{discovery.NewTargetFromMap(map[string]string{"__address__": "host:2222", "env": "prod", "instance": "wrong", "__param_target": "attacker", "__scheme__": "https"})}}
	out := buildTargets(base, a.targets())
	require.Len(t, out, 1)
	for key, want := range map[string]string{"instance": "host:2222", "__param_target": "host:2222", "__address__": "alloy.internal:12345", "__metrics_path__": "/component/metrics", "env": "prod", "job": "integrations/ssh"} {
		value, ok := out[0].Get(key)
		require.True(t, ok)
		require.Equal(t, want, value)
	}
}

func TestValidation(t *testing.T) {
	valid := func() Arguments {
		var a Arguments
		a.SetToDefault()
		a.Auths = []Auth{{Name: "default", Username: "reader", Password: "test-only"}}
		a.KnownHostsFiles = []string{"fixture"}
		a.Targets = []Target{{Address: "host"}}
		return a
	}
	require.NoError(t, valid().Validate())
	for _, tc := range []struct {
		name   string
		mutate func(*Arguments)
	}{
		{"unknown", func(a *Arguments) { a.EnabledCollectors = []string{"arbitrary"} }},
		{"duplicate", func(a *Arguments) { a.EnabledCollectors = []string{"cpu", "cpu"} }},
		{"regex", func(a *Arguments) { a.Netdev.DeviceExclude = "[" }},
		{"filesystem regex", func(a *Arguments) { a.Filesystem.FSTypesExclude = "[" }},
		{"auth", func(a *Arguments) { a.Targets[0].Auth = "missing" }},
		{"duplicate target", func(a *Arguments) { a.Targets = append(a.Targets, a.Targets[0]) }},
		{"ambiguous", func(a *Arguments) {
			a.TargetsList = []discovery.Target{discovery.NewTargetFromMap(map[string]string{"__address__": "host"})}
		}},
		{"URL", func(a *Arguments) { a.Targets[0].Address = "ssh://host" }},
		{"port", func(a *Arguments) { a.Targets[0].Address = "host:0" }},
		{"timeout", func(a *Arguments) { a.Timeout = 0 }},
		{"sessions", func(a *Arguments) { a.MaxSessionsPerTarget = 10 }},
		{"trust", func(a *Arguments) { a.KnownHostsFiles = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) { a := valid(); tc.mutate(&a); require.Error(t, a.Validate()) })
	}
	a := valid()
	a.Netdev.DeviceInclude = "eth"
	a.Netdev.DeviceExclude = "["
	require.NoError(t, a.Validate())
}
