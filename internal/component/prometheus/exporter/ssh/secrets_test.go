package ssh

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/discovery"
	localfile "github.com/grafana/alloy/internal/component/local/file"
	"github.com/grafana/alloy/internal/component/prometheus/exporter"
	"github.com/grafana/alloy/internal/component/prometheus/scrape"
	"github.com/grafana/alloy/internal/component/remote/vault"
	"github.com/grafana/alloy/internal/util"
	"github.com/grafana/alloy/syntax"
	"github.com/grafana/alloy/syntax/alloytypes"
	"github.com/grafana/alloy/syntax/parser"
	"github.com/grafana/alloy/syntax/vm"
)

func TestSecretSources(t *testing.T) {
	// Real source components produce the exports evaluated by Alloy's real VM.
	// All secret values here are synthetic, and the Vault API is loopback only.
	filename := filepath.Join(t.TempDir(), "synthetic-password")
	require.NoError(t, os.WriteFile(filename, []byte("test-password"), 0600))
	var fileExports localfile.Exports
	opts := component.Options{Logger: util.TestAlloyLogger(t).Slog(), Registerer: prometheus.NewRegistry(), OnStateChange: func(e component.Exports) { fileExports = e.(localfile.Exports) }}
	var fileArgs localfile.Arguments
	fileArgs.SetToDefault()
	fileArgs.Filename = filename
	fileArgs.IsSecret = true
	fileComponent, err := localfile.New(opts, fileArgs)
	require.NoError(t, err)
	require.True(t, fileExports.Content.IsSecret)
	// Run with a canceled context to release the file detector.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = fileComponent.Run(ctx) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/secret/data/ssh", r.URL.Path)
		require.Equal(t, "synthetic-token", r.Header.Get("X-Vault-Token"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"data":{"password":"vault-password"},"metadata":{"version":1}},"lease_duration":0,"renewable":false}`)
	}))
	defer server.Close()
	var vaultExports vault.Exports
	opts.Registerer = prometheus.NewRegistry()
	opts.OnStateChange = func(e component.Exports) { vaultExports = e.(vault.Exports) }
	var vaultArgs vault.Arguments
	vaultArgs.SetToDefault()
	vaultArgs.Server = server.URL
	vaultArgs.Path = "secret"
	vaultArgs.Key = "ssh"
	vaultArgs.Auth = []vault.AuthArguments{{AuthToken: &vault.AuthToken{Token: "synthetic-token"}}}
	_, err = vault.New(opts, vaultArgs)
	require.NoError(t, err)
	require.Equal(t, alloytypes.Secret("vault-password"), vaultExports.Data["password"])
	scope := vm.NewScope(map[string]any{
		"local":  map[string]any{"file": map[string]any{"password": fileExports}},
		"remote": map[string]any{"vault": map[string]any{"ssh": vaultExports}},
	})
	for _, tc := range []struct{ expr, want string }{{"local.file.password.content", "test-password"}, {"remote.vault.ssh.data.password", "vault-password"}} {
		t.Run(tc.expr, func(t *testing.T) {
			file, err := parser.ParseFile("", []byte(fmt.Sprintf(`
 known_hosts_files = ["fixture"]
 auth "default" {
 username = "reader"
 password = %s
 }
 target "host" { address = "host" }
 `, tc.expr)))
			require.NoError(t, err)
			var args Arguments
			require.NoError(t, vm.New(file).Evaluate(scope, &args))
			require.Equal(t, alloytypes.Secret(tc.want), args.Auths[0].Password)
			require.Equal(t, []byte(tc.want), args.poolConfig().Auths["default"].Password)
			text, err := syntax.Marshal(args)
			require.NoError(t, err)
			require.NotContains(t, string(text), tc.want)
		})
	}
}

func TestClusteredScrapeConsumesExports(t *testing.T) {
	targets := buildTargets(discovery.NewTargetFromMap(map[string]string{"__address__": "alloy.internal:12345", "__metrics_path__": "/metrics", "job": "integrations/ssh"}), []Target{{Address: "linux:22"}, {Address: "other:22"}})
	scope := vm.NewScope(map[string]any{"prometheus": map[string]any{"exporter": map[string]any{"ssh": map[string]any{"hosts": exporter.Exports{Targets: targets}}}}})
	file, err := parser.ParseFile("", []byte(`targets = prometheus.exporter.ssh.hosts.targets
 forward_to = []
 clustering { enabled = true }
 `))
	require.NoError(t, err)
	var args scrape.Arguments
	require.NoError(t, vm.New(file).Evaluate(scope, &args))
	require.True(t, args.Clustering.Enabled)
	require.Equal(t, targets, args.Targets)
	for i, address := range []string{"linux:22", "other:22"} {
		instance, _ := args.Targets[i].Get("instance")
		param, _ := args.Targets[i].Get("__param_target")
		require.Equal(t, address, instance)
		require.Equal(t, address, param)
	}
}
