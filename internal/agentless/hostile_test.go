//go:build hostile

package agentless_test

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/grafana/alloy/internal/agentless/collectors"
	"github.com/grafana/alloy/internal/util"
)

// Match the security review's seven nearly-1-MiB sections, not a reduced
// cardinality proxy. Filesystem parsing makes this a slow, opt-in test.
func hostileResults() map[string]agentless.Result {
	fill := func(header string, line func(int) string) []byte {
		var b strings.Builder
		b.WriteString(header)
		for i := 0; ; i++ {
			l := line(i)
			if b.Len()+len(l) > (1<<20)-1 {
				break
			}
			b.WriteString(l)
		}
		return []byte(b.String())
	}
	r := map[string]agentless.Result{}
	put := func(read agentless.Read, out []byte) { r[read.ID] = agentless.Result{Read: read, Output: out} }
	put(agentless.FileRead("/proc/stat"), fill("cpu 0 0 0 0\n", func(i int) string { return fmt.Sprintf("cpu%d 1\n", i) }))
	put(agentless.FileRead("/proc/diskstats"), fill("", func(i int) string { return fmt.Sprintf("1 1 d%d 0 0 0 0 0 0 0 0 0 0 0\n", i) }))
	put(agentless.FileRead("/proc/net/dev"), fill("Inter-|\nface |\n", func(i int) string { return fmt.Sprintf("n%d:0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", i) }))
	put(agentless.FileRead("/proc/meminfo"), fill("", func(i int) string { return fmt.Sprintf("M%d: 1\n", i) }))
	put(agentless.FileRead("/proc/self/mounts"), fill("", func(i int) string { return fmt.Sprintf("x /m%d e rw 0 0\n", i) }))
	df := fill("Filesystem\n", func(i int) string { return fmt.Sprintf("x e 1 0 1 0%% /m%d\n", i) })
	put(agentless.CommandRead("env", "LC_ALL=C", "df", "-akPT"), df)
	put(agentless.CommandRead("env", "LC_ALL=C", "df", "-aiPT"), df)
	return r
}

func TestHostileAllCollectorsHeap(t *testing.T) {
	cs, err := collectors.Build([]string{"cpu", "diskstats", "filesystem", "meminfo", "netdev", "stat"}, collectors.DefaultConfigs(), util.TestLogger(t))
	require.NoError(t, err)
	runner := &agentlesstest.FakeRunner{Results: hostileResults()}
	total := 0
	for _, res := range runner.Results {
		total += len(res.Output)
	}
	require.Greater(t, total, 7300000)
	s, err := agentless.NewScraper(runner, cs, util.TestLogger(t))
	require.NoError(t, err)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var peak atomic.Uint64
	peak.Store(before.HeapInuse)
	stopSampling := make(chan struct{})
	samplingDone := make(chan struct{})
	go func() {
		defer close(samplingDone)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			var sample runtime.MemStats
			runtime.ReadMemStats(&sample)
			if sample.HeapInuse > peak.Load() {
				peak.Store(sample.HeapInuse)
			}
			select {
			case <-stopSampling:
				return
			case <-ticker.C:
			}
		}
	}()
	stopSampler := sync.OnceFunc(func() { close(stopSampling); <-samplingDone })
	t.Cleanup(stopSampler)
	start := time.Now()
	c, err := s.Scrape(t.Context(), agentless.Target{Address: "host:22", Auth: "default"})
	require.NoError(t, err)
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(c))
	families, err := reg.Gather()
	require.NoError(t, err)
	stopSampler()
	runtime.ReadMemStats(&after)
	if after.HeapInuse > peak.Load() {
		peak.Store(after.HeapInuse)
	}
	series := 0
	for _, f := range families {
		series += len(f.Metric)
	}
	t.Logf("input=%d bytes families=%d series=%d elapsed=%s total_alloc=%d heap_in_use=%d baseline=%d", total, len(families), series, time.Since(start), after.TotalAlloc-before.TotalAlloc, after.HeapInuse, before.HeapInuse)
	t.Logf("sampled peak heap_in_use=%d", peak.Load())
	require.Less(t, peak.Load(), uint64(64<<20), "hostile processing must stay below 64 MiB of sampled heap")
	require.Less(t, after.HeapInuse, uint64(64<<20), "hostile all-collector Gather must use less than 64 MiB of heap")
	require.LessOrEqual(t, series, len(cs)*(20000+2))
	runtime.KeepAlive(cs)
	runtime.KeepAlive(families)
}
