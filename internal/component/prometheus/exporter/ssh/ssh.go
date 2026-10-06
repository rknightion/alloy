package ssh

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/collectors"
	"github.com/grafana/alloy/internal/agentless/sshrunner"
	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/discovery"
	"github.com/grafana/alloy/internal/component/prometheus/exporter"
	"github.com/grafana/alloy/internal/featuregate"
	httpservice "github.com/grafana/alloy/internal/service/http"
)

func init() {
	component.Register(component.Registration{
		Name: "prometheus.exporter.ssh", Stability: featuregate.StabilityExperimental,
		Args: Arguments{}, Exports: exporter.Exports{},
		Build: func(opts component.Options, args component.Arguments) (component.Component, error) {
			return New(opts, args.(Arguments))
		},
	})
}

// Component owns one connection pool for its entire lifetime.
type Component struct {
	opts            component.Options
	mu              sync.RWMutex
	pool            *sshrunner.Pool
	scraper         *agentless.Scraper
	collectorNames  []string
	collectorConfig collectors.Configs
	allowed         map[string]agentless.Target
	timeout         time.Duration
	base            discovery.Target
}

var _ component.Component = (*Component)(nil)

func New(opts component.Options, args Arguments) (*Component, error) {
	if err := args.Validate(); err != nil {
		return nil, err
	}
	data, err := opts.GetServiceData(httpservice.ServiceName)
	if err != nil {
		return nil, fmt.Errorf("get HTTP service: %w", err)
	}
	httpData := data.(httpservice.Data)
	c := &Component{opts: opts, base: discovery.NewTargetFromMap(map[string]string{
		"__address__": httpData.MemoryListenAddr, "__scheme__": "http",
		"__metrics_path__": path.Join(httpData.HTTPPathForComponent(opts.ID), "metrics"),
		"job":              "integrations/ssh", "__meta_component_name": opts.ID[:strings.LastIndex(opts.ID, ".")],
		"__meta_component_id": opts.ID,
	})}
	c.pool, err = sshrunner.New(args.poolConfig(), opts.Logger, opts.Registerer)
	if err != nil {
		return nil, err
	}
	if err := c.Update(args); err != nil {
		_ = c.pool.Close()
		return nil, err
	}
	return c, nil
}

// Run closes all live connections when the component stops.
func (c *Component) Run(ctx context.Context) error { <-ctx.Done(); return c.pool.Close() }

// Update reconfigures the existing pool rather than replacing it.
func (c *Component) Update(raw component.Arguments) error {
	args := raw.(Arguments)
	if err := args.Validate(); err != nil {
		return err
	}
	allowed := make(map[string]agentless.Target)
	for _, t := range args.targets() {
		allowed[t.Address] = agentless.Target{Address: t.Address, Auth: t.Auth}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cfg := args.collectorConfigs()
	scraper := c.scraper
	if scraper == nil || !slices.Equal(c.collectorNames, args.EnabledCollectors) || c.collectorConfig != cfg {
		cs, err := collectors.Build(args.EnabledCollectors, cfg, c.opts.Logger)
		if err != nil {
			return err
		}
		scraper, err = agentless.NewScraper(c.pool, cs, c.opts.Logger)
		if err != nil {
			return err
		}
	}
	if err := c.pool.Update(args.poolConfig()); err != nil {
		return err
	}
	// Preserve stateful collectors across target, credential and timeout-only
	// updates; the lifetime pool remains the scraper's runner.
	c.collectorNames, c.collectorConfig = slices.Clone(args.EnabledCollectors), cfg
	c.scraper, c.allowed, c.timeout = scraper, allowed, args.Timeout
	c.opts.OnStateChange(exporter.Exports{Targets: buildTargets(c.base, args.targets())})
	return nil
}

func buildTargets(base discovery.Target, targets []Target) []discovery.Target {
	out := make([]discovery.Target, 0, len(targets))
	for _, t := range targets {
		labels := make(map[string]string, len(t.Labels)+base.Len()+2)
		for k, v := range t.Labels {
			if !strings.HasPrefix(k, "__") {
				labels[k] = v
			}
		}
		base.ForEachLabel(func(k, v string) bool { labels[k] = v; return true })
		labels["instance"], labels["__param_target"] = t.Address, t.Address
		out = append(out, discovery.NewTargetFromMap(labels))
	}
	return out
}

// Handler exposes the component's multi-target metrics endpoint.
func (c *Component) Handler() http.Handler { return http.HandlerFunc(c.serveHTTP) }

func (c *Component) serveHTTP(w http.ResponseWriter, r *http.Request) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	params := query["target"]
	if err != nil || len(params) != 1 || params[0] == "" {
		http.Error(w, "exactly one configured target is required", http.StatusBadRequest)
		return
	}
	metrics, cancel, status, err := c.collect(r, params[0])
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	// Collectors run lazily during Gather, so retain the deadline context
	// through HTTP collection rather than cancelling after the SSH batch.
	defer cancel()
	// Metrics are immutable after collection. Never retain the configuration
	// lock during HTTP delivery: a stalled client must not block revocation.
	registry := prometheus.NewRegistry()
	if err := registry.Register(metrics); err != nil {
		http.Error(w, "metrics registration failed", http.StatusInternalServerError)
		return
	}
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError}).ServeHTTP(w, r)
}

func (c *Component) collect(r *http.Request, address string) (prometheus.Collector, context.CancelFunc, int, error) {
	// Serialize collection with credential updates, but not response writes.
	c.mu.RLock()
	defer c.mu.RUnlock()
	target, ok := c.allowed[address]
	if !ok {
		return nil, nil, http.StatusBadRequest, fmt.Errorf("unknown target")
	}
	timeout, err := scrapeTimeout(r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"), c.timeout)
	if err != nil {
		return nil, nil, http.StatusBadRequest, err
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	started := time.Now()
	metrics, err := c.scraper.Scrape(ctx, target)
	if err != nil {
		// Prometheus discards samples on HTTP 503. Its built-in target up=0
		// and scrape_duration_seconds observe failures; do not depend on
		// non-ingestible health samples in the rejected response body.
		// Never expose server-controlled or credential-bearing errors.
		cancel()
		return nil, nil, http.StatusServiceUnavailable, fmt.Errorf("SSH scrape failed")
	}
	return &scrapeMetrics{node: metrics, up: 1, duration: time.Since(started)}, cancel, http.StatusOK, nil
}

func scrapeTimeout(header string, cap time.Duration) (time.Duration, error) {
	if header == "" {
		return cap, nil
	}
	seconds, err := strconv.ParseFloat(header, 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds <= 0 {
		return 0, fmt.Errorf("invalid scrape timeout")
	}
	// Compare before converting to avoid overflow from untrusted headers.
	if seconds >= cap.Seconds()+0.5 {
		return cap, nil
	}
	timeout := time.Duration(seconds*float64(time.Second)) - 500*time.Millisecond
	if timeout <= 0 {
		return 0, fmt.Errorf("scrape timeout must exceed 500ms")
	}
	return timeout, nil
}
