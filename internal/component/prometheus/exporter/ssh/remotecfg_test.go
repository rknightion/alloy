package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/batch"
	"github.com/grafana/alloy/internal/agentless/collectors"
	"github.com/grafana/alloy/internal/component"
	localfile "github.com/grafana/alloy/internal/component/local/file"
	"github.com/grafana/alloy/internal/component/prometheus/exporter"
	"github.com/grafana/alloy/internal/featuregate"
	alloyruntime "github.com/grafana/alloy/internal/runtime"
	"github.com/grafana/alloy/internal/service"
	httpservice "github.com/grafana/alloy/internal/service/http"
	"github.com/grafana/alloy/internal/service/remotecfg"
	"github.com/grafana/alloy/internal/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Only the network/process edge is substituted. Capture stdin before replacing
// Linux procfs paths, then execute the real batch framing with a bounded shell.
func remotePipelineServer(t *testing.T) (string, string, <-chan string) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gossh.NewSignerFromKey(key)
	require.NoError(t, err)
	cfg := &gossh.ServerConfig{PasswordCallback: func(meta gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
		if (meta.User() == "reader" && string(password) == "test-only") || (meta.User() == "reader;$(echo USER_CANARY)" && string(password) == "$(echo PASSWORD_CANARY);'\n") {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	scripts := make(chan string, 32)
	done := make(chan struct{})
	var connections sync.WaitGroup
	t.Cleanup(func() {
		require.NoError(t, listener.Close())
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("remote pipeline SSH server did not stop")
		}
	})
	paths := make(map[string]string)
	for _, name := range []string{"stat", "loadavg"} {
		path, err := filepath.Abs(filepath.Join("testdata", "remote", name))
		require.NoError(t, err)
		paths["/proc/"+name] = path
	}
	go func() {
		defer close(done)
		defer connections.Wait()
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(4 * time.Second))
				conn, channels, requests, err := gossh.NewServerConn(raw, cfg)
				if err != nil {
					return
				}
				defer conn.Close()
				go gossh.DiscardRequests(requests)
				for ch := range channels {
					if ch.ChannelType() != "session" {
						_ = ch.Reject(gossh.UnknownChannelType, "unsupported")
						continue
					}
					channel, reqs, err := ch.Accept()
					if err != nil {
						return
					}
					for req := range reqs {
						var payload struct{ Command string }
						if req.Type != "exec" || gossh.Unmarshal(req.Payload, &payload) != nil || payload.Command != batch.RemoteCommand {
							_ = req.Reply(false, nil)
							continue
						}
						_ = req.Reply(true, nil)
						script, err := io.ReadAll(io.LimitReader(channel, 1<<20))
						if err != nil {
							break
						}
						scripts <- string(script)
						fixed := string(script)
						for path, fixture := range paths {
							fixed = strings.ReplaceAll(fixed, path, strconv.Quote(fixture))
						}
						ctx, cancel := context.WithTimeout(context.Background(), time.Second)
						cmd := exec.CommandContext(ctx, "sh", "-s")
						cmd.Stdin, cmd.Stdout, cmd.Stderr = strings.NewReader(fixed), channel, io.Discard
						cmd.WaitDelay = 100 * time.Millisecond
						status := uint32(0)
						if cmd.Run() != nil {
							status = 1
						}
						cancel()
						_, _ = channel.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{status}))
						break
					}
					_ = channel.Close()
				}
			}()
		}
	}()
	address := listener.Addr().String()
	return address, knownhosts.Line([]string{address}, signer.PublicKey()), scripts
}

func TestRemoteConfigPipeline(t *testing.T) {
	address, trust, scripts := remotePipelineServer(t)
	logger := util.TestAlloyLogger(t)
	reg := prometheus.NewRegistry()
	httpSvc := httpservice.New(httpservice.Options{Logger: logger, Gatherer: reg, HTTPListenAddr: "127.0.0.1:0", MemoryListenAddr: "remote-pipeline", MinStability: featuregate.StabilityExperimental})
	remoteSvc, err := remotecfg.New(remotecfg.Options{Logger: logger.Slog(), Metrics: reg, StoragePath: t.TempDir()})
	require.NoError(t, err)
	root, err := alloyruntime.New(alloyruntime.Options{Logger: logger, Reg: reg, DataPath: t.TempDir(), MinStability: featuregate.StabilityExperimental, Services: []service.Service{httpSvc, remoteSvc}})
	require.NoError(t, err)
	source, err := alloyruntime.ParseSource("root", nil)
	require.NoError(t, err)
	require.NoError(t, root.LoadSource(source, nil, ""))
	// This is precisely the production isolated module controller and LoadSource
	// used by remotecfg.configManager.parseAndLoad, not a syntax-only decode.
	ctrl, err := root.NewController("remotecfg")
	require.NoError(t, err)
	host := ctrl.(alloyruntime.ServiceController).GetHost()
	ctx, cancel := context.WithTimeout(t.Context(), 9*time.Second)
	rootDone, ctrlDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(rootDone); root.Run(ctx) }()
	go func() { defer close(ctrlDone); ctrl.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		for _, done := range []chan struct{}{ctrlDone, rootDone} {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("pipeline controller did not stop")
			}
		}
	})
	template, err := os.ReadFile("testdata/remote/pipeline.alloy")
	require.NoError(t, err)
	type variant struct{ names, selection, address, username, password, label, filter, trust string }
	base := variant{"cpu", "cpu", address, "reader", "test-only", "local", "eth.*", trust}
	load := func(v variant) error {
		credential := filepath.Join(t.TempDir(), "password")
		require.NoError(t, os.WriteFile(credential, []byte(v.password), 0600))
		names := strings.Split(v.names, ",")
		for i := range names {
			names[i] = strconv.Quote(names[i])
		}
		config := strings.NewReplacer(
			"@CREDENTIAL@", strconv.Quote(credential), "@TRUST@", strconv.Quote(v.trust),
			"@COLLECTORS@", `[`+strings.Join(names, ",")+`]`, "@SELECTION@", strconv.Quote(v.selection),
			"@ADDRESS@", strconv.Quote(v.address), "@USERNAME@", strconv.Quote(v.username),
			"@LABEL@", strconv.Quote(v.label), "@FILTER@", strconv.Quote(v.filter),
		).Replace(string(template))
		_, err := ctrl.LoadSource([]byte(config), nil, "fleet.alloy")
		return err
	}
	scrape := func(v variant, status int) string {
		t.Helper()
		info, err := host.GetComponent(component.ID{LocalID: "prometheus.exporter.ssh.fleet"}, component.InfoOptions{GetArguments: true, GetExports: true})
		require.NoError(t, err)
		args := info.Arguments.(Arguments)
		require.Equal(t, v.password, string(args.Auths[0].Password), "secret producer must reach transport credentials")
		require.Equal(t, v.trust, args.KnownHosts.Value)
		credential, err := host.GetComponent(component.ID{LocalID: "local.file.credential"}, component.InfoOptions{GetExports: true})
		require.NoError(t, err)
		require.True(t, credential.Exports.(localfile.Exports).Content.IsSecret)
		targets := info.Exports.(exporter.Exports).Targets
		require.Len(t, targets, 1)
		label, _ := targets[0].Get("environment")
		require.Equal(t, v.label, label)
		query := url.Values{}
		for _, name := range []string{"target", "auth", "collectors"} {
			value, ok := targets[0].Get("__param_" + name)
			require.True(t, ok)
			query.Set(name, value)
		}
		w := httptest.NewRecorder()
		info.Component.(*Component).Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics?"+query.Encode(), nil))
		require.Equal(t, status, w.Code, w.Body.String())
		return w.Body.String()
	}
	const normalizedNonce = "00000000000000000000000000000000"
	noncePattern := regexp.MustCompile(`[0-9a-f]{32}:[0-9]+:begin`)
	var fixedPlanScript string
	for _, names := range []string{"cpu", "stat", "cpu,stat", "loadavg"} {
		for _, hostile := range []bool{false, true} {
			v := base
			v.names, v.selection = names, names
			if hostile {
				v.username, v.password = "reader;$(echo USER_CANARY)", "$(echo PASSWORD_CANARY);'\n"
				v.label, v.filter = "';$(echo LABEL_CANARY)\n", "FILTER_CANARY;[$]\\(echo.*\\)"
				v.address = strings.Replace(address, "127.0.0.1", "localhost", 1)
				// Trust the second spelling too; no insecure host-key callback is used.
				v.trust = trust + "\n" + strings.Replace(trust, "127.0.0.1", "localhost", 1)
			}
			t.Run(v.selection+"/"+strconv.FormatBool(hostile), func(t *testing.T) {
				require.NoError(t, load(v))
				body := scrape(v, http.StatusOK)
				for _, name := range strings.Split(v.selection, ",") {
					require.Contains(t, body, `node_scrape_collector_success{collector="`+name+`"} 1`)
				}
				switch v.selection {
				case "cpu", "cpu,stat":
					require.Contains(t, body, `node_cpu_seconds_total{cpu="0",mode="user"} 10`)
				case "stat":
					require.Contains(t, body, "node_intr_total 42")
				case "loadavg":
					require.Contains(t, body, "node_load1 1.5")
				}
				var script string
				select {
				case script = <-scripts:
				case <-ctx.Done():
					t.Fatal("SSH script not observed")
				}
				marker := noncePattern.FindString(script)
				require.NotEmpty(t, marker)
				normalized := strings.ReplaceAll(script, strings.Split(marker, ":")[0], normalizedNonce)
				cs, err := collectors.Build(strings.Split(v.selection, ","), collectors.DefaultConfigs(), logger.Slog())
				require.NoError(t, err)
				plan, err := agentless.NewScraper(nil, cs, logger.Slog())
				require.NoError(t, err)
				expected, err := batch.Build(plan.Reads(), normalizedNonce)
				require.NoError(t, err)
				require.Equal(t, expected, normalized, "wire stdin must contain only compiled Reads, never argument text")
				if v.selection != "loadavg" {
					if fixedPlanScript == "" {
						fixedPlanScript = normalized
					}
					require.Equal(t, fixedPlanScript, normalized, "CPU/stat names share exactly the same /proc/stat Read plan")
				} else {
					require.NotEqual(t, fixedPlanScript, normalized, "different legitimate Read plans need not have identical scripts")
				}
			})
		}
	}
	for _, name := range []string{"unknown", "cpu;echo NAME_CANARY", "$(echo NAME_CANARY)"} {
		t.Run("reject/"+name, func(t *testing.T) {
			v := base
			v.names, v.selection = name, name
			require.Error(t, load(v), "unknown global collector must be rejected by loader")
			v.names = "cpu"
			require.NoError(t, load(v), "invalid discovery selection remains a target-local failure")
			scrape(v, http.StatusServiceUnavailable)
			select {
			case script := <-scripts:
				t.Fatalf("invalid name reached SSH: %s", script)
			default:
			}
		})
	}
	for _, failure := range []string{"credential", "trust"} {
		t.Run(failure+" genuinely required", func(t *testing.T) {
			v := base
			if failure == "credential" {
				v.password = "wrong"
			} else {
				v.trust = "# no trusted hosts"
			}
			require.NoError(t, load(v))
			scrape(v, http.StatusServiceUnavailable)
			select {
			case script := <-scripts:
				t.Fatalf("untrusted or unauthenticated request sent script: %s", script)
			default:
			}
		})
	}
}
