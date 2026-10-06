package ssh

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/discovery"
	"github.com/grafana/alloy/internal/component/prometheus/exporter"
	httpservice "github.com/grafana/alloy/internal/service/http"
	"github.com/grafana/alloy/internal/util"
	"github.com/grafana/alloy/syntax/alloytypes"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func selectedDiscoveryTarget(address, auth, names string) discovery.Target {
	return discovery.NewTargetFromMap(map[string]string{"__address__": address, "__param_auth": auth, "__param_collectors": names})
}

func selectionComponent(t *testing.T, args Arguments) (*Component, *exporter.Exports) {
	t.Helper()
	var exports exporter.Exports
	c, err := New(component.Options{
		ID: "prometheus.exporter.ssh.test", Logger: util.TestAlloyLogger(t).Slog(), Registerer: prometheus.NewRegistry(),
		OnStateChange: func(e component.Exports) { exports = e.(exporter.Exports) },
		GetServiceData: func(string) (any, error) {
			return httpservice.Data{MemoryListenAddr: "alloy.internal:12345", BaseHTTPPath: "/"}, nil
		},
	}, args)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.pool.Close()) })
	return c, &exports
}

func selectionRequest(t *testing.T, c *Component, address, suffix string, status int) string {
	t.Helper()
	w := httptest.NewRecorder()
	c.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics?target="+url.QueryEscape(address)+suffix, nil))
	require.Equal(t, status, w.Code, w.Body.String())
	return w.Body.String()
}

// Keep this independent of invalid-membership and exported-label assertions:
// the pre-selector handler must reach these public HTTP checks and return 200,
// not fail on credentials, setup, or membership before selector enforcement.
func TestDiscoveryHTTPSelectorSnapshot(t *testing.T) {
	address, trust, authenticated := inlineSSHServer(t)
	var args Arguments
	args.SetToDefault()
	args.Auths = []Auth{{Name: "default", Username: "reader", Password: "test-only"}, {Name: "selected", Username: "reader", Password: "test-only"}}
	args.KnownHosts = alloytypes.OptionalSecret{Value: trust}
	args.EnabledCollectors = []string{"loadavg", "uname"}
	args.Timeout, args.DialTimeout = time.Second, time.Second
	args.TargetsList = []discovery.Target{selectedDiscoveryTarget(address, "selected", "loadavg")}
	c, _ := selectionComponent(t, args)
	body := selectionRequest(t, c, address, "", http.StatusOK)
	require.Contains(t, body, `node_scrape_collector_success{collector="loadavg"}`)
	require.EqualValues(t, 1, authenticated.Load(), "public handler reached the real SSH server")
	for _, tc := range []struct{ name, suffix string }{
		{"declared credential switch", "&auth=default"},
		{"undeclared credential", "&auth=undeclared"},
		{"collector broadening", "&collectors=loadavg,uname"},
		{"duplicate auth", "&auth=selected&auth=selected"},
		{"empty collectors", "&collectors="},
		{"duplicate collectors", "&collectors=loadavg&collectors=loadavg"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selectionRequest(t, c, address, tc.suffix, http.StatusBadRequest)
		})
	}
	t.Run("omitted and matching selectors", func(t *testing.T) {
		for _, suffix := range []string{"", "&auth=selected&collectors=loadavg"} {
			body := selectionRequest(t, c, address, suffix, http.StatusOK)
			require.Contains(t, body, `node_scrape_collector_success{collector="loadavg"}`)
			require.NotContains(t, body, `collector="uname"`)
		}
	})
	require.EqualValues(t, 1, authenticated.Load(), "rejected requests do not switch credentials or reconnect")
}

func TestDiscoverySelectionSnapshot(t *testing.T) {
	address, trust, authenticated := inlineSSHServer(t)
	var args Arguments
	args.SetToDefault()
	args.Auths = []Auth{{Name: "default", Username: "reader", Password: "wrong"}, {Name: "selected", Username: "reader", Password: "test-only"}}
	args.KnownHosts = alloytypes.OptionalSecret{Value: trust}
	args.EnabledCollectors = []string{"loadavg", "uname"}
	args.Timeout, args.DialTimeout = time.Second, time.Second
	args.TargetsList = []discovery.Target{
		selectedDiscoveryTarget(address, "selected", "loadavg"),
		selectedDiscoveryTarget("bad-auth", "undeclared", "loadavg"),
		selectedDiscoveryTarget("bad-collector", "selected", "cpu"),
		selectedDiscoveryTarget("unknown-collector", "selected", "unknown"),
		selectedDiscoveryTarget("duplicate-collector", "selected", "loadavg,loadavg"),
	}
	require.NoError(t, args.Validate())
	require.Len(t, args.poolConfig().Targets, 1, "invalid selectors must not enter pool membership")
	c, exports := selectionComponent(t, args)
	require.Len(t, exports.Targets, 5)
	for key, want := range map[string]string{"__param_auth": "selected", "__param_collectors": "loadavg"} {
		got, _ := exports.Targets[0].Get(key)
		require.Equal(t, want, got)
	}
	body := selectionRequest(t, c, address, "", http.StatusOK)
	require.Contains(t, body, `node_scrape_collector_success{collector="loadavg"}`)
	require.NotContains(t, body, `collector="uname"`)
	for _, address := range []string{"bad-auth", "bad-collector", "unknown-collector", "duplicate-collector"} {
		require.Equal(t, "SSH scrape failed\n", selectionRequest(t, c, address, "", http.StatusServiceUnavailable))
	}
	require.EqualValues(t, 1, authenticated.Load())
	args.TargetsList = []discovery.Target{selectedDiscoveryTarget(address, "selected", "uname")}
	require.NoError(t, c.Update(args))
	selectionRequest(t, c, address, "&collectors=loadavg", http.StatusBadRequest)
	body = selectionRequest(t, c, address, "&auth=selected&collectors=uname", http.StatusOK)
	require.Contains(t, body, `collector="uname"`)
	require.NotContains(t, body, `collector="loadavg"`)
}

func TestDiscoveryCPUCounterContinuity(t *testing.T) {
	procStat := filepath.Join(t.TempDir(), "stat")
	writeStat := func(user string) {
		t.Helper()
		// Idle stays constant: a backwards user counter is not CPU hotplug.
		require.NoError(t, os.WriteFile(procStat, []byte("cpu "+user+" 0 0 1000 0 0 0 0 0 0\ncpu0 "+user+" 0 0 1000 0 0 0 0 0 0\n"), 0o600))
	}
	writeStat("1000")
	domainname := filepath.Join(t.TempDir(), "domainname")
	require.NoError(t, os.WriteFile(domainname, []byte("(none)\n"), 0o600))
	address, trust, _ := inlineSSHServerWithFiles(t, map[string]string{"/proc/stat": procStat, "/proc/sys/kernel/domainname": domainname})
	var args Arguments
	args.SetToDefault()
	args.Auths = []Auth{{Name: "default", Username: "reader", Password: "test-only"}}
	args.KnownHosts = alloytypes.OptionalSecret{Value: trust}
	args.EnabledCollectors = []string{"cpu", "uname"}
	args.Timeout, args.DialTimeout = time.Second, time.Second
	args.TargetsList = []discovery.Target{selectedDiscoveryTarget(address, "", "cpu")}
	c, exports := selectionComponent(t, args)
	body := selectionRequest(t, c, address, "", http.StatusOK)
	require.Contains(t, body, `node_scrape_collector_success{collector="cpu"} 1`)
	require.Contains(t, body, `node_cpu_seconds_total{cpu="0",mode="user"} 10`)
	require.NotContains(t, body, `collector="uname"`)

	// Change the discovery selection and metadata, not the global collector
	// configuration. A newly built CPU instance would incorrectly emit 9.
	writeStat("900")
	labels := map[string]string{"__address__": address, "__param_collectors": "cpu,uname", "env": "updated"}
	args.TargetsList = []discovery.Target{discovery.NewTargetFromMap(labels)}
	require.NoError(t, c.Update(args))
	value, _ := exports.Targets[0].Get("env")
	require.Equal(t, "updated", value)
	body = selectionRequest(t, c, address, "&auth=default&collectors=cpu,uname", http.StatusOK)
	require.Contains(t, body, `node_scrape_collector_success{collector="cpu"} 1`)
	require.Contains(t, body, `node_scrape_collector_success{collector="uname"} 1`)
	require.Contains(t, body, `node_cpu_seconds_total{cpu="0",mode="user"} 10`, "discovery selection update must retain the backwards-counter guard")
	require.NotContains(t, body, `node_cpu_seconds_total{cpu="0",mode="user"} 9`)

	// A label-only update and then a return to the original subset must also
	// preserve the guard; these requests use the current exported snapshot.
	for _, names := range []string{"cpu,uname", "cpu"} {
		writeStat("800")
		labels["__param_collectors"], labels["env"] = names, "latest"
		args.TargetsList = []discovery.Target{discovery.NewTargetFromMap(labels)}
		require.NoError(t, c.Update(args))
		value, _ := exports.Targets[0].Get("env")
		require.Equal(t, "latest", value)
		body = selectionRequest(t, c, address, "", http.StatusOK)
		require.Contains(t, body, `node_scrape_collector_success{collector="cpu"} 1`)
		require.Contains(t, body, `node_cpu_seconds_total{cpu="0",mode="user"} 10`)
		require.NotContains(t, body, `node_cpu_seconds_total{cpu="0",mode="user"} 8`)
		if names == "cpu" {
			require.NotContains(t, body, `collector="uname"`)
		}
	}
}

func TestDiscoverySelectionDefaults(t *testing.T) {
	var args Arguments
	args.SetToDefault()
	args.Auths = []Auth{{Name: "default", Username: "reader", Password: "test-only"}}
	args.KnownHostsFiles = []string{"fixture"}
	args.TargetsList = []discovery.Target{selectedDiscoveryTarget("host", "", "")}
	for _, names := range [][]string{nil, {"cpu", "uname"}} {
		args.EnabledCollectors = names
		require.NoError(t, args.Validate())
		out := buildTargets(discovery.NewTargetFromMap(nil), args.targets())
		auth, _ := out[0].Get("__param_auth")
		got, _ := out[0].Get("__param_collectors")
		require.Equal(t, "default", auth)
		require.NotEmpty(t, got)
		if names != nil {
			require.Equal(t, "cpu,uname", got)
		}
		require.Len(t, args.poolConfig().Targets, 1)
	}
	args.Auths[0].Name = "other"
	require.NoError(t, args.Validate(), "missing discovery default is a target failure")
	require.Empty(t, args.poolConfig().Targets)
}
