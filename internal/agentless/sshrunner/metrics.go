package sshrunner

import "github.com/prometheus/client_golang/prometheus"

const (
	dialErrorAuth    = "auth"
	dialErrorHostKey = "host_key"
	dialErrorTimeout = "timeout"
	dialErrorRefused = "refused"
	dialErrorOther   = "other"
)

// Pool metrics are component-wide aggregates. No series is keyed by target,
// auth selection, credentials or remote error text, including retired entries.
type poolMetrics struct {
	open         prometheus.GaugeFunc
	sessions     prometheus.Gauge
	dials        prometheus.Counter
	errors       *prometheus.CounterVec
	hostFailures prometheus.Counter
}

func newPoolMetrics(p *Pool) *poolMetrics {
	m := &poolMetrics{
		open: prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "agentless_ssh_open_connections", Help: "Current usable SSH connections in the pool."}, func() float64 {
			p.mu.Lock()
			defer p.mu.Unlock()
			var n int
			for _, e := range p.entries {
				if e.client != nil {
					n++
				}
			}
			return float64(n)
		}),
		sessions:     prometheus.NewGauge(prometheus.GaugeOpts{Name: "agentless_ssh_sessions_in_use", Help: "SSH session slots currently in use, including closing sessions."}),
		dials:        prometheus.NewCounter(prometheus.CounterOpts{Name: "agentless_ssh_dials_total", Help: "SSH connection attempts, including trust checks before TCP connection."}),
		errors:       prometheus.NewCounterVec(prometheus.CounterOpts{Name: "agentless_ssh_dial_errors_total", Help: "Failed SSH connection attempts by bounded reason."}, []string{"reason"}),
		hostFailures: p.hostFailures,
	}
	// Pre-create only this fixed vocabulary. Unknown transport failures are not
	// forced into one of the actionable classes or labelled with raw error text.
	for _, reason := range []string{dialErrorAuth, dialErrorHostKey, dialErrorTimeout, dialErrorRefused, dialErrorOther} {
		m.errors.WithLabelValues(reason)
	}
	return m
}

func (m *poolMetrics) Describe(ch chan<- *prometheus.Desc) {
	for _, c := range []prometheus.Collector{m.open, m.sessions, m.dials, m.errors, m.hostFailures} {
		c.Describe(ch)
	}
}

func (m *poolMetrics) Collect(ch chan<- prometheus.Metric) {
	for _, c := range []prometheus.Collector{m.open, m.sessions, m.dials, m.errors, m.hostFailures} {
		c.Collect(ch)
	}
}
