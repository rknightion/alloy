package agentless

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Namespace is the metric namespace of every collector, matching
// node_exporter so that existing dashboards and alerts work unchanged.
const Namespace = "node"

// Limits apply to each collector independently, before Gather can materialize
// target-controlled output. Keep the Collector interface independent of policy.
const (
	maxCollectorSeries   = 20000
	maxCollectorFamilies = 500
	maxLabelValueBytes   = 4096
)

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

// MaxExpandedReads bounds the reads returned by one Expander.
const MaxExpandedReads = 1024

// MaxExpandedReadsPerScrape bounds the deduplicated additional reads executed
// in phase two. A collector that would exceed it is rejected in its entirety.
const MaxExpandedReadsPerScrape = 4096

// Scraper runs the fixed batch and, when needed, one expansion batch per scrape.
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

// Scrape runs the batches against target and returns a prometheus.Collector
// holding the parsed metrics. It returns an error when the batch could not run
// at all; a caller serving HTTP should then fail the scrape so that the
// scraper's up metric reports the target as down.
//
// The returned collector emits, per collector, node_scrape_collector_success
// (1 when expansion succeeded and Update returned nil without panicking,
// exceeding output limits or ending the scrape context) and
// node_scrape_collector_duration_seconds (the time spent in Update, which
// excludes the remote round trip shared by the whole batch). Serve it with
// promhttp's ContinueOnError so that one bad series does not fail the scrape.
func (s *Scraper) Scrape(ctx context.Context, target Target) (prometheus.Collector, error) {
	in, err := s.run(ctx, target, s.reads)
	if err != nil {
		return nil, err
	}
	failures := make([]error, len(s.collectors))
	seen := make(map[string]Read, len(s.reads))
	for _, read := range s.reads {
		seen[read.ID] = read
	}
	var expanded []Read
	participants := make([]bool, len(s.collectors))
	for i, c := range s.collectors {
		e, ok := c.(Expander)
		if !ok {
			continue
		}
		reads, err := expand(ctx, e, target, in)
		if err == nil && len(reads) > MaxExpandedReads {
			err = fmt.Errorf("collector expanded read limit exceeded")
		}
		// Validate atomically: a bad final read must not schedule any of this
		// collector's reads or consume capacity needed by another collector.
		var additional []Read
		local := make(map[string]Read)
		if err == nil {
			for _, read := range reads {
				if err = read.Validate(); err != nil {
					break
				}
				prev, exists := seen[read.ID]
				if !exists {
					prev, exists = local[read.ID]
				}
				if exists {
					if !sameRead(prev, read) {
						err = fmt.Errorf("read ID %q is used for two different reads", read.ID)
						break
					}
					continue
				}
				local[read.ID] = read
				additional = append(additional, read)
			}
		}
		if err == nil && len(expanded)+len(additional) > MaxExpandedReadsPerScrape {
			err = fmt.Errorf("scrape expanded read limit exceeded")
		}
		if err != nil {
			failures[i] = err
			continue
		}
		for _, read := range additional {
			seen[read.ID] = read
		}
		expanded = append(expanded, additional...)
		for _, read := range reads {
			if _, present := in[read.ID]; !present {
				participants[i] = true
			}
		}
	}
	if len(expanded) != 0 {
		second, err := s.run(ctx, target, expanded)
		if err != nil {
			// The fixed batch remains trustworthy; only collectors needing
			// phase-two results fail when that batch cannot be trusted.
			for i, participant := range participants {
				if participant {
					failures[i] = err
				}
			}
		} else {
			for id, result := range second {
				in[id] = result
			}
		}
	}
	return &scrapeResult{ctx: ctx, collectors: s.collectors, in: in, target: target, logger: s.logger, failures: failures}, nil
}

// run validates the Runner's framing contract before exposing any results.
func (s *Scraper) run(ctx context.Context, target Target, reads []Read) (Input, error) {
	results, err := s.runner.Run(ctx, target, reads)
	if err != nil {
		return nil, err
	}
	if len(results) != len(reads) {
		return nil, fmt.Errorf("runner returned %d results for %d reads", len(results), len(reads))
	}
	in := make(Input, len(results))
	for i, res := range results {
		if res.Read.ID != reads[i].ID {
			return nil, fmt.Errorf("runner returned result %q at position %d, want %q", res.Read.ID, i, reads[i].ID)
		}
		in[res.Read.ID] = res
	}
	return in, nil
}

func expand(ctx context.Context, e Expander, target Target, in Input) (reads []Read, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("collector %s expansion panicked: %v", e.Name(), p)
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return e.Expand(target, in)
}

type scrapeResult struct {
	ctx        context.Context
	collectors []Collector
	in         Input
	target     Target
	logger     *slog.Logger
	failures   []error
}

// Describe implements prometheus.Collector. The result is an unchecked
// collector: its metrics depend on what the target reports.
func (r *scrapeResult) Describe(chan<- *prometheus.Desc) {}

// Collect implements prometheus.Collector.
func (r *scrapeResult) Collect(ch chan<- prometheus.Metric) {
	for i, c := range r.collectors {
		start := time.Now()
		err := r.failures[i]
		var metrics []prometheus.Metric
		if err == nil {
			metrics, err = r.buffer(c)
		}
		for _, m := range metrics {
			ch <- m
		}
		duration := time.Since(start)

		success := 1.0
		if err != nil {
			success = 0
			if r.logger != nil {
				r.logger.Debug("collector failed", "target", r.target.Address, "collector", c.Name(), "err", err)
			}
		}
		ch <- prometheus.MustNewConstMetric(scrapeDurationDesc, prometheus.GaugeValue, duration.Seconds(), c.Name())
		ch <- prometheus.MustNewConstMetric(scrapeSuccessDesc, prometheus.GaugeValue, success, c.Name())
	}
}

// bufferedMetric exports the same serialized metric that was checked, without
// retaining any producer-owned state or calling its Write method again.
type bufferedMetric struct {
	desc   *prometheus.Desc
	metric *dto.Metric
}

func (m bufferedMetric) Desc() *prometheus.Desc { return m.desc }
func (m bufferedMetric) Write(out *dto.Metric) error {
	// Copy only exported payload fields, not protobuf's internal mutex/state.
	out.Label = m.metric.Label
	out.Gauge = m.metric.Gauge
	out.Counter = m.metric.Counter
	out.Summary = m.metric.Summary
	out.Untyped = m.metric.Untyped
	out.Histogram = m.metric.Histogram
	out.TimestampMs = m.metric.TimestampMs
	return nil
}

// buffer runs the producer with an unbuffered channel. Once rejected, output is
// drained without serialization or retention, so a finite producer always exits.
// The frozen Collector interface cannot interrupt an Update already in progress.
func (r *scrapeResult) buffer(c Collector) ([]prometheus.Metric, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	ch := make(chan prometheus.Metric)
	done := make(chan error, 1)
	go func() {
		done <- r.update(c, ch)
		close(ch)
	}()
	var metrics []prometheus.Metric
	families := make(map[string]struct{})
	var err error
	for m := range ch {
		if err == nil {
			err = r.ctx.Err()
		}
		if err == nil && len(metrics) == maxCollectorSeries {
			err = fmt.Errorf("collector series limit exceeded")
		}
		if err == nil {
			var checked bufferedMetric
			var family string
			checked, family, err = checkMetric(m)
			if err == nil {
				families[family] = struct{}{}
				if len(families) > maxCollectorFamilies {
					err = fmt.Errorf("collector family limit exceeded")
				} else {
					metrics = append(metrics, checked)
				}
			}
		}
		if err != nil {
			metrics = nil
		}
	}
	updateErr := <-done
	if err == nil {
		err = r.ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	// Preserve valid partial output on an ordinary producer error or panic,
	// as required by Collector. Policy rejection discards the whole buffer.
	return metrics, updateErr
}

// checkMetric checks all labels, including const labels. Desc's public String
// representation supplies the family name; the descriptor's full string also
// includes label names and const values and is not a family identity.
func checkMetric(m prometheus.Metric) (checked bufferedMetric, family string, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("metric panicked: %v", p)
		}
	}()
	checked.desc = m.Desc()
	name, ok := strings.CutPrefix(checked.desc.String(), `Desc{fqName: `)
	if !ok {
		return checked, "", fmt.Errorf("invalid metric descriptor")
	}
	quoted, err := strconv.QuotedPrefix(name)
	if err != nil {
		return checked, "", fmt.Errorf("invalid metric family: %w", err)
	}
	family, err = strconv.Unquote(quoted)
	if err != nil {
		return checked, "", fmt.Errorf("invalid metric family: %w", err)
	}
	checked.metric = &dto.Metric{}
	if err = m.Write(checked.metric); err != nil {
		return checked, family, err
	}
	for _, label := range checked.metric.Label {
		if len(label.GetValue()) > maxLabelValueBytes {
			return checked, family, fmt.Errorf("collector label value limit exceeded")
		}
	}
	return checked, family, nil
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
