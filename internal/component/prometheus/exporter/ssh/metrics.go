package ssh

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	upDesc       = prometheus.NewDesc("agentless_ssh_up", "Whether the SSH batch returned trustworthy results for this target.", nil, nil)
	durationDesc = prometheus.NewDesc("agentless_ssh_scrape_duration_seconds", "SSH scrape duration in seconds, including remote round trip but excluding HTTP delivery.", nil, nil)
)

// Health belongs only to the already target-carrying scrape response. These
// immutable samples have no target labels and are never registered in the
// component registry, so target churn cannot retain health series there.
type scrapeMetrics struct {
	node     prometheus.Collector
	up       float64
	duration time.Duration
}

func (*scrapeMetrics) Describe(chan<- *prometheus.Desc) {}

func (m *scrapeMetrics) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(upDesc, prometheus.GaugeValue, m.up)
	ch <- prometheus.MustNewConstMetric(durationDesc, prometheus.GaugeValue, m.duration.Seconds())
	if m.node != nil {
		m.node.Collect(ch)
	}
}
