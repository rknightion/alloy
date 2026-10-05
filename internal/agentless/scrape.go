package agentless

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Namespace is the metric namespace of every collector, matching
// node_exporter so that existing dashboards and alerts work unchanged.
const Namespace = "node"

var (
	scrapeDurationDesc = prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, "scrape", "collector_duration_seconds"),
		"node_exporter: Duration of a collector scrape.",
		[]string{"collector"}, nil,
	)
	scrapeSuccessDesc = prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, "scrape", "collector_success"),
		"node_exporter: Whether a collector succeeded.",
		[]string{"collector"}, nil,
	)
)

// Scraper runs one batch per scrape for a fixed set of collectors.
type Scraper struct {
	runner     Runner
	collectors []Collector
	reads      []Read
	logger     *slog.Logger
}

// NewScraper returns a Scraper that runs the reads of collectors through
// runner. Reads with the same ID are executed once and shared. It returns an
// error when a read is invalid or two different reads share an ID.
func NewScraper(runner Runner, collectors []Collector, logger *slog.Logger) (*Scraper, error) {
	var (
		reads []Read
		seen  = make(map[string]Read)
	)
	for _, c := range collectors {
		for _, r := range c.Reads() {
			if err := r.Validate(); err != nil {
				return nil, fmt.Errorf("collector %s: %w", c.Name(), err)
			}
			if prev, ok := seen[r.ID]; ok {
				if !sameRead(prev, r) {
					return nil, fmt.Errorf("collector %s: read ID %q is used for two different reads", c.Name(), r.ID)
				}
				continue
			}
			seen[r.ID] = r
			reads = append(reads, r)
		}
	}
	return &Scraper{runner: runner, collectors: collectors, reads: reads, logger: logger}, nil
}

// Reads returns the deduplicated batch the Scraper runs on every scrape.
func (s *Scraper) Reads() []Read { return s.reads }

// Scrape runs the batch against target and returns a prometheus.Collector
// holding the parsed metrics. It returns an error when the batch could not run
// at all; a caller serving HTTP should then fail the scrape so that the
// scraper's up metric reports the target as down.
//
// The returned collector emits, per collector, node_scrape_collector_success
// (1 when Update returned nil without panicking) and
// node_scrape_collector_duration_seconds (the time spent in Update, which
// excludes the remote round trip shared by the whole batch). Serve it with
// promhttp's ContinueOnError so that one bad series does not fail the scrape.
func (s *Scraper) Scrape(ctx context.Context, target Target) (prometheus.Collector, error) {
	results, err := s.runner.Run(ctx, target, s.reads)
	if err != nil {
		return nil, err
	}
	if len(results) != len(s.reads) {
		return nil, fmt.Errorf("runner returned %d results for %d reads", len(results), len(s.reads))
	}
	in := make(Input, len(results))
	for i, res := range results {
		if res.Read.ID != s.reads[i].ID {
			return nil, fmt.Errorf("runner returned result %q at position %d, want %q", res.Read.ID, i, s.reads[i].ID)
		}
		in[res.Read.ID] = res
	}
	return &scrapeResult{collectors: s.collectors, in: in, target: target, logger: s.logger}, nil
}

type scrapeResult struct {
	collectors []Collector
	in         Input
	target     Target
	logger     *slog.Logger
}

// Describe implements prometheus.Collector. The result is an unchecked
// collector: its metrics depend on what the target reports.
func (r *scrapeResult) Describe(chan<- *prometheus.Desc) {}

// Collect implements prometheus.Collector.
func (r *scrapeResult) Collect(ch chan<- prometheus.Metric) {
	for _, c := range r.collectors {
		start := time.Now()
		err := r.update(c, ch)
		duration := time.Since(start)

		success := 1.0
		if err != nil {
			success = 0
			r.logger.Debug("collector failed", "target", r.target.Address, "collector", c.Name(), "err", err)
		}
		ch <- prometheus.MustNewConstMetric(scrapeDurationDesc, prometheus.GaugeValue, duration.Seconds(), c.Name())
		ch <- prometheus.MustNewConstMetric(scrapeSuccessDesc, prometheus.GaugeValue, success, c.Name())
	}
}

// update runs one collector, turning a panic into an error so that output a
// hostile or unusual target controls cannot take down the whole scrape.
func (r *scrapeResult) update(c Collector, ch chan<- prometheus.Metric) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("collector %s panicked: %v", c.Name(), p)
		}
	}()
	return c.Update(r.target, r.in, ch)
}

func sameRead(a, b Read) bool {
	if a.Path != b.Path || len(a.Argv) != len(b.Argv) {
		return false
	}
	for i := range a.Argv {
		if a.Argv[i] != b.Argv[i] {
			return false
		}
	}
	return true
}
