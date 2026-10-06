package collectors

import (
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
)

const (
	cpuSubsystem = "cpu"
	cpuStateTTL  = time.Hour
)

func init() {
	Register(Registration{Name: cpuSubsystem, OS: "linux", DefaultEnabled: true, Factory: newCPUCollector})
}

type cpuTargetState struct {
	times     map[int64]cpuTimes
	updatedAt time.Time
}

type cpuCollector struct {
	mu         sync.Mutex
	stats      map[agentless.Target]cpuTargetState
	now        func() time.Time
	nextExpiry time.Time
}

func newCPUCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &cpuCollector{stats: make(map[agentless.Target]cpuTargetState), now: time.Now}, nil
}

// Name implements agentless.Collector.
func (c *cpuCollector) Name() string { return cpuSubsystem }

// Reads implements agentless.Collector.
func (c *cpuCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/stat")}
}

var (
	cpuSecondsDesc      = prometheus.NewDesc(prometheus.BuildFQName(agentless.Namespace, cpuSubsystem, "seconds_total"), "Seconds the CPUs spent in each mode.", []string{cpuSubsystem, "mode"}, nil)
	cpuGuestSecondsDesc = prometheus.NewDesc(prometheus.BuildFQName(agentless.Namespace, cpuSubsystem, "guest_seconds_total"), "Seconds the CPUs spent in guests (VMs) for each mode.", []string{cpuSubsystem, "mode"}, nil)
)

// Update implements agentless.Collector.
func (c *cpuCollector) Update(target agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	// Prune on every Update, including failed reads of unrelated targets.
	// No background worker is needed when scraping stops altogether.
	c.mu.Lock()
	now := c.now()
	// Most scrapes cannot expire anything. Only scan the target map when
	// its earliest known expiry is due, rather than on every target scrape.
	if !c.nextExpiry.IsZero() && !now.Before(c.nextExpiry) {
		c.nextExpiry = time.Time{}
		for target, state := range c.stats {
			expires := state.updatedAt.Add(cpuStateTTL)
			if !now.Before(expires) {
				delete(c.stats, target)
			} else if c.nextExpiry.IsZero() || expires.Before(c.nextExpiry) {
				c.nextExpiry = expires
			}
		}
	}
	c.mu.Unlock()

	parsed, err := readProcStat(in)
	if err != nil {
		return err
	}

	// Build a per-call snapshot under the lock, then release it before sending
	// metrics so a slow consumer cannot block unrelated targets.
	c.mu.Lock()
	previous := c.stats[target].times
	for id, next := range parsed.cpus {
		old := previous[id]
		// Match node_exporter's hotplug heuristic, including the exact boundary.
		if old[3]-next[3] >= 3 {
			old = cpuTimes{}
		}
		for i := range next {
			if next[i] < old[i] {
				next[i] = old[i]
			}
		}
		parsed.cpus[id] = next
	}
	// Replacing the map also removes every offline CPU, even when the number
	// of CPUs stays constant but the set of IDs changes.
	updatedAt := c.now()
	c.stats[target] = cpuTargetState{times: parsed.cpus, updatedAt: updatedAt}
	expires := updatedAt.Add(cpuStateTTL)
	if c.nextExpiry.IsZero() || expires.Before(c.nextExpiry) {
		c.nextExpiry = expires
	}
	c.mu.Unlock()

	for id, times := range parsed.cpus {
		cpu := strconv.FormatInt(id, 10)
		for i, mode := range []string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"} {
			ch <- prometheus.MustNewConstMetric(cpuSecondsDesc, prometheus.CounterValue, times[i], cpu, mode)
		}
		// Do not subtract guests from user/nice: Linux already includes them in
		// those counters, as does node_exporter. Guests have a separate family.
		ch <- prometheus.MustNewConstMetric(cpuGuestSecondsDesc, prometheus.CounterValue, times[8], cpu, "user")
		ch <- prometheus.MustNewConstMetric(cpuGuestSecondsDesc, prometheus.CounterValue, times[9], cpu, "nice")
	}
	return nil
}
