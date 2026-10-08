//go:build hostile

package agentless_test

import (
	"context"
	"fmt"
	"runtime"
	"slices"
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

// Exercise the opted-in ceiling at the real batch and Gather boundaries. One
// nearly-1-MiB listing is poisoned at a time so earlier failures cannot hide it.
func TestHostileDeepListingLimit512Heap(t *testing.T) {
	for _, hostileIndex := range []int{-1, 0, 511} {
		t.Run(fmt.Sprint(hostileIndex), func(t *testing.T) {
			second := make([]agentless.Read, 0, 512)
			results := make(map[string]agentless.Result)
			for i := range 512 {
				read := agentless.CommandRead("ls", "-1", fmt.Sprintf("/sys/device%d", i))
				second = append(second, read)
				output := []byte("value\n")
				if i == hostileIndex {
					output = []byte(strings.Repeat("value\n", ((1<<20)-1)/6))
					require.Greater(t, len(output), 1000000)
					require.Less(t, len(output), 1<<20)
				}
				results[read.ID] = agentless.Result{Output: output}
				file := agentless.FileRead(fmt.Sprintf("/sys/device%d/value", i))
				results[file.ID] = agentless.Result{Output: []byte("1\n")}
			}
			updates := 0
			base := capDeepCollector("limited", second, nil, &updates)
			base.deep = func(_ agentless.Target, in agentless.Input) ([]agentless.Read, error) {
				var third []agentless.Read
				for i, read := range second {
					output, err := in.Output(read)
					if err != nil {
						return nil, err
					}
					for _, name := range strings.Fields(string(output)) {
						third = append(third, agentless.FileRead(fmt.Sprintf("/sys/device%d/%s", i, name)))
						if len(third) > 512 {
							return nil, fmt.Errorf("too many discovered files")
						}
					}
				}
				return third, nil
			}
			runner := &hostileExpandedRunner{FakeRunner: agentlesstest.FakeRunner{Results: results}}
			scraper, err := agentless.NewScraper(runner, []agentless.Collector{limitedDeepCollector{base, 512}}, util.TestLogger(t))
			require.NoError(t, err)
			runtime.GC()
			var peak atomic.Uint64
			var after runtime.MemStats
			sample := func() {
				var stats runtime.MemStats
				runtime.ReadMemStats(&stats)
				if stats.HeapInuse > peak.Load() {
					peak.Store(stats.HeapInuse)
				}
			}
			sample()
			stop, done := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(done)
				ticker := time.NewTicker(time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						sample()
					case <-stop:
						return
					}
				}
			}()
			stopSampler := sync.OnceFunc(func() { close(stop); <-done })
			t.Cleanup(stopSampler)
			result, err := scraper.Scrape(t.Context(), agentless.Target{Address: "host:22"})
			require.NoError(t, err)
			reg := prometheus.NewRegistry()
			require.NoError(t, reg.Register(result))
			families, err := reg.Gather()
			require.NoError(t, err)
			stopSampler()
			runtime.ReadMemStats(&after)
			sample()
			require.Less(t, peak.Load(), uint64(64<<20), "hostile processing must stay below 64 MiB of sampled heap")
			require.Less(t, after.HeapInuse, uint64(64<<20), "hostile Gather must use less than 64 MiB of heap")
			require.Len(t, runner.batches[1], 512)
			want, wantCalls := 1.0, 3
			if hostileIndex >= 0 {
				want, wantCalls = 0, 2
			}
			require.Len(t, runner.batches, wantCalls)
			if wantCalls == 3 {
				require.Len(t, runner.batches[2], 512, "both phases share the unchanged 1024 read budget")
			}
			series, statuses := 0, 0
			for _, family := range families {
				switch family.GetName() {
				case "node_scrape_collector_success":
					statuses++
					require.Equal(t, want, family.Metric[0].GetGauge().GetValue())
				case "node_scrape_collector_duration_seconds":
				default:
					series += len(family.Metric)
				}
			}
			require.Equal(t, 1, statuses)
			require.Equal(t, int(want), series, "hostile rejection is atomic")
			require.Equal(t, int(want), updates)
			t.Logf("hostile_index=%d listings=512 sampled_peak=%d heap_in_use=%d", hostileIndex, peak.Load(), after.HeapInuse)
			runtime.KeepAlive(families)
		})
	}
}

// hostileExpandedRunner records the real batch boundary, not just Expand output.
type hostileExpandedRunner struct {
	agentlesstest.FakeRunner
	batches [][]agentless.Read
}

func (r *hostileExpandedRunner) Run(ctx context.Context, target agentless.Target, reads []agentless.Read) ([]agentless.Result, error) {
	r.batches = append(r.batches, append([]agentless.Read(nil), reads...))
	return r.FakeRunner.Run(ctx, target, reads)
}

func hostileNetclassExpanded(t *testing.T, collector agentless.Collector) {
	t.Helper()
	attributes := []string{"addr_assign_type", "carrier", "carrier_changes", "carrier_up_count", "carrier_down_count", "dev_id", "dormant", "flags", "ifindex", "iflink", "link_mode", "mtu", "name_assign_type", "netdev_group", "speed", "tx_queue_len", "type", "address", "broadcast", "duplex", "operstate", "ifalias"}
	cases := []string{"baseline", "eleven", "twelve", "forty-six", "forty-seven", "invalid_names", "failed_attribute", "hostile_listing"}
	cases = append(cases, attributes...)
	for _, mode := range cases {
		t.Run(mode, func(t *testing.T) {
			listing := collector.Reads()[0]
			count, wantCalls, wantSuccess := 1, 2, 1.0
			switch mode {
			case "eleven":
				count = 11
			case "twelve":
				count = 12
			case "forty-six":
				count = 46
			case "forty-seven":
				count, wantCalls, wantSuccess = 47, 1, 0
			}
			var names strings.Builder
			results := map[string]agentless.Result{}
			for i := range count {
				device := fmt.Sprintf("eth%d", i)
				fmt.Fprintln(&names, device)
				for _, attribute := range attributes {
					read := agentless.FileRead("/sys/class/net/" + device + "/" + attribute)
					value := "1\n"
					if attribute == "operstate" {
						value = "up\n"
					}
					result := agentless.Result{Read: read, Output: []byte(value)}
					if attribute == mode {
						result.Output = []byte(strings.Repeat("x", (1<<20)-1))
						wantSuccess = 0
					}
					if mode == "failed_attribute" && attribute == "speed" {
						result.ExitStatus = 1
					}
					results[read.ID] = result
				}
			}
			if mode == "invalid_names" {
				names.WriteString("../evil\nbad name\nx/y\n.\nbonding_masters\n")
			}
			if mode == "hostile_listing" {
				names.Reset()
				names.WriteString(strings.Repeat("x\n", ((1<<20)-2)/2))
				wantCalls, wantSuccess = 1, 0
			}
			results[listing.ID] = agentless.Result{Read: listing, Output: []byte(names.String())}
			runner := &hostileExpandedRunner{FakeRunner: agentlesstest.FakeRunner{Results: results}}
			scraper, err := agentless.NewScraper(runner, []agentless.Collector{collector}, util.TestLogger(t))
			require.NoError(t, err)
			result, err := scraper.Scrape(t.Context(), agentless.Target{Address: "host:22"})
			require.NoError(t, err)
			reg := prometheus.NewRegistry()
			require.NoError(t, reg.Register(result))
			families, err := reg.Gather()
			require.NoError(t, err)
			require.Equal(t, wantCalls, runner.Calls())
			if wantCalls == 2 {
				require.Len(t, runner.batches[1], count*22)
				for _, read := range runner.batches[1] {
					require.NoError(t, read.Validate())
					require.Empty(t, read.Argv)
					require.Contains(t, results, read.ID)
				}
			}
			series, statuses := 0, 0
			for _, family := range families {
				switch family.GetName() {
				case "node_scrape_collector_success":
					statuses++
					require.Equal(t, wantSuccess, family.Metric[0].GetGauge().GetValue())
				case "node_scrape_collector_duration_seconds":
				default:
					series += len(family.Metric)
				}
			}
			require.Equal(t, 1, statuses)
			if wantSuccess == 0 {
				require.Zero(t, series, "failure must be atomic")
			} else {
				wantSeries := count * 19
				if mode == "failed_attribute" {
					wantSeries--
				}
				require.Equal(t, wantSeries, series)
			}
			t.Logf("case=%s batches=%d expanded=%d series=%d success=%g", mode, runner.Calls(), (wantCalls-1)*count*22, series, wantSuccess)
		})
	}
}

// hostileHardwareRunner supplies ordinary attribute values while recording the
// actual execution boundary. Only the compiled listing paths receive names.
type hostileHardwareRunner struct {
	batches  [][]agentless.Read
	fixed    map[string]agentless.Result
	mode     string
	deepRows int
}

func (r *hostileHardwareRunner) Run(_ context.Context, _ agentless.Target, reads []agentless.Read) ([]agentless.Result, error) {
	r.batches = append(r.batches, append([]agentless.Read(nil), reads...))
	results := make([]agentless.Result, 0, len(reads))
	for i, read := range reads {
		result := agentless.Result{Read: read, Output: []byte("1\n")}
		if fixed, ok := r.fixed[read.ID]; ok {
			result = fixed
		} else if len(read.Argv) != 0 {
			var listing strings.Builder
			for j := range r.deepRows {
				fmt.Fprintf(&listing, "csrow%d\n", j)
			}
			result.Output = []byte(listing.String())
			if r.mode == "hostile_deep_listing" {
				result.Output = []byte(strings.Repeat("ignored\n", ((1<<20)-1)/8))
			}
		} else if strings.HasSuffix(read.Path, "/bonding/slaves") {
			result.Output = []byte("eth0\n")
		} else if strings.HasSuffix(read.Path, "/bonding_slave/mii_status") {
			result.Output = []byte("up\n")
		}
		// Fail the last attribute, after earlier valid attributes, to prove
		// whole-collector failure rather than a retained partial snapshot.
		if r.mode == "failed_attribute" && len(r.batches) == 2 && i == len(reads)-1 {
			result.ExitStatus = 1
		}
		results = append(results, result)
	}
	return results, nil
}

func hostileHardwareExpanded(t *testing.T, collector agentless.Collector) {
	t.Helper()
	name := collector.Name()
	prefix, width, limit := "", 0, 0
	switch name {
	case "thermal_zone":
		prefix, width, limit = "thermal_zone", 4, 256
	case "cpufreq":
		prefix, width, limit = "cpu", 8, 128
	case "bonding":
		prefix, width, limit = "eth", 1, 1023 // One additional primary-interface read.
	case "powersupplyclass":
		prefix, width, limit = "BAT", 60, 17
	case "nvme":
		prefix, width, limit = "nvme", 5, 204
	case "edac":
		prefix, width, limit = "mc", 5, 64
	default:
		t.Fatalf("missing expanded fixture for %s", name)
	}
	modes := []string{"baseline", "at_cap", "over_cap", "hostile_listing", "failed_attribute", "missing_listing", "truncated_missing"}
	if name == "edac" {
		modes = append(modes, "deep_at_cap", "deep_over_cap", "hostile_deep_listing")
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			count, wantSuccess, wantCalls, deepRows := 1, 1.0, 2, 1
			if name == "edac" {
				wantCalls = 3
			}
			switch mode {
			case "at_cap":
				count = limit
			case "over_cap":
				count, wantSuccess, wantCalls = limit+1, 0, 1
			case "hostile_listing", "truncated_missing":
				wantSuccess, wantCalls = 0, 1
			case "missing_listing":
				wantCalls = 1
			case "failed_attribute":
				wantSuccess = 0 // Attribute errors surface during Update, after all planned phases.
			case "deep_at_cap":
				deepRows = 509 // 5 + 509*2 = 1023 shared additional reads.
			case "deep_over_cap":
				deepRows, wantSuccess, wantCalls = 510, 0, 2
			case "hostile_deep_listing":
				wantSuccess, wantCalls = 0, 2
			}
			var listing strings.Builder
			for i := range count {
				fmt.Fprintf(&listing, "%s%d\n", prefix, i)
			}
			fixed := map[string]agentless.Result{}
			reads := collector.Reads()
			for _, read := range reads {
				result := agentless.Result{Read: read, Output: []byte(listing.String())}
				if read.Path != "" {
					result.Output = []byte("bond0\n")
				}
				switch mode {
				case "hostile_listing":
					result.Output = []byte(strings.Repeat("ignored\n", ((1<<20)-1)/8))
				case "missing_listing", "truncated_missing":
					result.Output, result.NotExist, result.ExitStatus = nil, true, 1
					result.Truncated = mode == "truncated_missing"
				}
				fixed[read.ID] = result
			}
			runner := &hostileHardwareRunner{fixed: fixed, mode: mode, deepRows: deepRows}
			s, err := agentless.NewScraper(runner, []agentless.Collector{collector}, util.TestLogger(t))
			require.NoError(t, err)
			result, err := s.Scrape(t.Context(), agentless.Target{Address: "host:22"})
			require.NoError(t, err)
			reg := prometheus.NewRegistry()
			require.NoError(t, reg.Register(result))
			families, err := reg.Gather()
			require.NoError(t, err)
			require.Len(t, runner.batches, wantCalls)
			require.Equal(t, reads, runner.batches[0])
			if wantCalls >= 2 {
				wantReads := count * width
				if name == "bonding" {
					wantReads++
				}
				require.Len(t, runner.batches[1], wantReads)
				listings := 0
				for _, read := range runner.batches[1] {
					require.NoError(t, read.Validate())
					if len(read.Argv) != 0 {
						listings++
						require.Equal(t, "edac", name)
						require.Len(t, read.Argv, 3)
						require.Equal(t, []string{"ls", "-1"}, read.Argv[:2])
						require.Contains(t, read.Argv[2], "/sys/devices/system/edac/mc/mc")
					}
				}
				if name == "edac" {
					require.Equal(t, count, listings)
				}
			}
			if wantCalls == 3 {
				require.Len(t, runner.batches[2], count*deepRows*2)
				for _, read := range runner.batches[2] {
					require.NoError(t, read.Validate())
					require.Empty(t, read.Argv)
					require.Contains(t, read.Path, "/csrow")
				}
			}
			series, statuses := 0, 0
			for _, family := range families {
				switch family.GetName() {
				case "node_scrape_collector_success":
					statuses++
					require.Len(t, family.Metric, 1)
					require.Equal(t, wantSuccess, family.Metric[0].GetGauge().GetValue())
				case "node_scrape_collector_duration_seconds":
				default:
					series += len(family.Metric)
				}
				for _, metric := range family.Metric {
					for _, label := range metric.Label {
						require.LessOrEqual(t, len(label.GetValue()), 4096)
					}
				}
			}
			require.Equal(t, 1, statuses)
			if wantSuccess == 0 || mode == "missing_listing" {
				require.Zero(t, series, "no partial data")
			} else {
				require.Positive(t, series)
			}
			require.LessOrEqual(t, series, 20000)
			t.Logf("collector=%s case=%s batches=%d series=%d success=%g", name, mode, len(runner.batches), series, wantSuccess)
		})
	}
}

// Exercise the global budget with real default collectors, including EDAC's
// third phase. These literals are independent of the production cap constants.
func TestHostileHardwareSharedExpansionBudget(t *testing.T) {
	for _, mode := range []string{"second_phase", "third_phase_at_cap", "third_phase_over_cap"} {
		t.Run(mode, func(t *testing.T) {
			names := []string{"cpufreq", "thermal_zone", "nvme", "powersupplyclass", "edac"}
			counts := map[string]int{"cpufreq": 128, "thermal_zone": 256, "nvme": 204, "powersupplyclass": 17, "edac": 1, "bonding": 1023}
			prefixes := map[string]string{"cpufreq": "cpu", "thermal_zone": "thermal_zone", "nvme": "nvme", "powersupplyclass": "BAT", "edac": "mc", "bonding": "eth"}
			wantFailed, wantCalls, wantSecond, deepRows := "", 3, 4093, 1
			switch mode {
			case "second_phase":
				names = []string{"cpufreq", "thermal_zone", "nvme", "bonding", "powersupplyclass"}
				wantFailed, wantCalls, wantSecond = "powersupplyclass", 2, 4092
			case "third_phase_over_cap":
				deepRows, wantFailed, wantCalls = 2, "edac", 2
			}
			cs, err := collectors.Build(names, collectors.DefaultConfigs(), util.TestLogger(t))
			require.NoError(t, err)
			fixed := map[string]agentless.Result{}
			for _, c := range cs {
				var listing strings.Builder
				for i := range counts[c.Name()] {
					fmt.Fprintf(&listing, "%s%d\n", prefixes[c.Name()], i)
				}
				for _, read := range c.Reads() {
					output := listing.String()
					if read.Path != "" {
						output = "bond0\n"
					}
					fixed[read.ID] = agentless.Result{Read: read, Output: []byte(output)}
				}
			}
			runner := &hostileHardwareRunner{fixed: fixed, deepRows: deepRows}
			s, err := agentless.NewScraper(runner, cs, util.TestLogger(t))
			require.NoError(t, err)
			result, err := s.Scrape(t.Context(), agentless.Target{Address: "host:22"})
			require.NoError(t, err)
			reg := prometheus.NewRegistry()
			require.NoError(t, reg.Register(result))
			families, err := reg.Gather()
			require.NoError(t, err)
			require.Len(t, runner.batches, wantCalls)
			require.Len(t, runner.batches[1], wantSecond)
			if wantCalls == 3 {
				require.Len(t, runner.batches[2], 2)
			}
			statuses := map[string]float64{}
			for _, family := range families {
				for _, metric := range family.Metric {
					if family.GetName() == "node_scrape_collector_success" {
						for _, label := range metric.Label {
							if label.GetName() == "collector" {
								statuses[label.GetValue()] = metric.GetGauge().GetValue()
							}
						}
					}
				}
				if wantFailed == "edac" {
					require.NotContains(t, family.GetName(), "node_edac_", "atomic failure")
				}
				if wantFailed == "powersupplyclass" {
					require.NotContains(t, family.GetName(), "node_power_supply_", "atomic failure")
				}
			}
			require.Len(t, statuses, len(cs))
			for _, name := range names {
				want := 1.0
				if name == wantFailed {
					want = 0
				}
				require.Equal(t, want, statuses[name], name)
			}
		})
	}
}

// These cases are also the dispatch table used by the default heap suite.
var hostileStorageCases = map[string]string{
	"fibrechannel": "host0\n",
	"tapestats":    "st0\n",
	"btrfs":        "11111111-1111-1111-1111-111111111111\n",
	"xfs":          "sda1\n",
	"bcache":       "11111111-1111-1111-1111-111111111111\n",
	"infiniband":   "mlx4_0\n",
}

func TestHostileDefaultCoverage(t *testing.T) {
	covered := []string{
		"arp", "bonding", "conntrack", "cpu", "cpufreq", "diskstats", "dmi", "edac", "entropy", "filefd", "filesystem", "ipvs", "loadavg", "mdadm", "meminfo", "netclass", "netdev", "netstat", "nfs", "nfsd", "nvme", "os", "powersupplyclass", "pressure", "schedstat", "selinux", "sockstat", "softnet", "stat", "thermal_zone", "udp_queues", "uname", "vmstat", "zfs",
	}
	for name := range hostileStorageCases {
		covered = append(covered, name)
	}
	slices.Sort(covered)
	require.Equal(t, collectors.DefaultEnabled(), covered, "every default needs an executable hostile case")
}

// Drive the real Scraper through all listing phases, then poison each read
// separately so a failed early attribute cannot mask an untested later one.
func hostileStorageExpanded(t *testing.T, collector agentless.Collector) {
	t.Helper()
	results := map[string]agentless.Result{}
	put := func(read agentless.Read, value string) {
		results[read.ID] = agentless.Result{Read: read, Output: []byte(value)}
	}
	listing := collector.Reads()[0]
	put(listing, hostileStorageCases[collector.Name()])
	second, err := collector.(agentless.Expander).Expand(agentless.Target{}, agentless.Input(results))
	require.NoError(t, err)
	for _, read := range second {
		value := "1\n"
		if len(read.Argv) != 0 {
			value = "single\n"
			if strings.HasSuffix(read.Argv[2], "/devices") {
				value = "sda\n"
			}
		} else if strings.HasSuffix(read.Path, "/metadata_uuid") {
			value = hostileStorageCases["btrfs"]
		}
		switch collector.Name() {
		case "xfs":
			value = "rw 1 2\n"
		case "bcache":
			if len(read.Argv) != 0 {
				value = "bdev0\ncache0\n"
			}
		case "infiniband":
			if len(read.Argv) != 0 {
				value = "1\n"
			}
		}
		put(read, value)
	}
	var third []agentless.Read
	if deep, ok := collector.(agentless.DeepExpander); ok {
		third, err = deep.ExpandDeep(agentless.Target{}, agentless.Input(results))
		require.NoError(t, err)
		for _, read := range third {
			value := "1\n"
			switch {
			case collector.Name() == "bcache" && strings.HasSuffix(read.Path, "/writeback_rate_debug"):
				value = "target: 1\nrate: 1/sec\nproportional: 1\nintegral: 1\nchange: 1\n"
			case collector.Name() == "infiniband" && strings.HasSuffix(read.Path, "/state"):
				value = "4: ACTIVE\n"
			case collector.Name() == "infiniband" && strings.HasSuffix(read.Path, "/phys_state"):
				value = "5: LinkUp\n"
			case collector.Name() == "infiniband" && strings.HasSuffix(read.Path, "/rate"):
				value = "40 Gb/sec\n"
			}
			put(read, value)
		}
	}
	reads := append(append(append([]agentless.Read{}, collector.Reads()...), second...), third...)
	for index := -1; index < len(reads); index++ {
		name := "baseline"
		if index >= 0 {
			name = fmt.Sprintf("read_%d", index)
		}
		t.Run(name, func(t *testing.T) {
			input := make(map[string]agentless.Result, len(results))
			for id, result := range results {
				input[id] = result
			}
			if index >= 0 {
				read := reads[index]
				output := []byte(strings.Repeat("x\n", ((1<<20)-2)/2))
				require.Greater(t, len(output), 1000000)
				require.Less(t, len(output), 1<<20)
				input[read.ID] = agentless.Result{Read: read, Output: output}
			}
			runner := &hostileExpandedRunner{FakeRunner: agentlesstest.FakeRunner{Results: input}}
			s, err := agentless.NewScraper(runner, []agentless.Collector{collector}, util.TestLogger(t))
			require.NoError(t, err)
			runtime.GC()
			var peak atomic.Uint64
			stop := make(chan struct{})
			done := make(chan struct{})
			sample := func() {
				var stats runtime.MemStats
				runtime.ReadMemStats(&stats)
				if stats.HeapInuse > peak.Load() {
					peak.Store(stats.HeapInuse)
				}
			}
			sample()
			go func() {
				defer close(done)
				ticker := time.NewTicker(time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						sample()
					case <-stop:
						return
					}
				}
			}()
			stopSampler := sync.OnceFunc(func() { close(stop); <-done })
			t.Cleanup(stopSampler)
			result, err := s.Scrape(t.Context(), agentless.Target{Address: "host:22"})
			require.NoError(t, err)
			reg := prometheus.NewRegistry()
			require.NoError(t, reg.Register(result))
			families, err := reg.Gather()
			require.NoError(t, err)
			stopSampler()
			sample()
			require.Less(t, peak.Load(), uint64(64<<20), "hostile storage processing must stay below 64 MiB of sampled heap")
			t.Logf("collector=%s case=%s sampled_peak=%d", collector.Name(), name, peak.Load())
			series, statuses := 0, 0
			for _, family := range families {
				switch family.GetName() {
				case "node_scrape_collector_success":
					statuses++
					require.Len(t, family.Metric, 1)
					want := 0.0
					if index < 0 {
						want = 1
					}
					require.Equal(t, want, family.Metric[0].GetGauge().GetValue())
				case "node_scrape_collector_duration_seconds":
				default:
					series += len(family.Metric)
				}
			}
			require.Equal(t, 1, statuses)
			if index < 0 {
				wantSeries, wantCalls := 15, 2
				switch collector.Name() {
				case "tapestats":
					wantSeries = 10
				case "btrfs":
					wantSeries, wantCalls = 15, 3
				case "xfs":
					wantSeries = 39
				case "bcache":
					wantSeries, wantCalls = 26, 3
				case "infiniband":
					wantSeries, wantCalls = 28, 3
				}
				require.Equal(t, wantSeries, series)
				require.Len(t, runner.batches, wantCalls)
				require.Equal(t, second, runner.batches[1])
				if wantCalls == 3 {
					require.Equal(t, third, runner.batches[2])
				}
			} else {
				require.Zero(t, series, "hostile reads must fail atomically")
			}
			for _, batch := range runner.batches {
				for _, read := range batch {
					require.NoError(t, read.Validate())
					require.Contains(t, input, read.ID)
				}
			}
		})
	}
}

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

// Exercise each declared read separately: making every read hostile at once
// would let an early parser error hide later reads (notably os-release fallback).
// Unlike the legacy six-collector proof above, this follows the default registry
// and fails closed when a new default or fixed read lacks a fixture.
func TestHostileDefaultCollectorsHeap(t *testing.T) {
	cs, err := collectors.Build(collectors.DefaultEnabled(), collectors.DefaultConfigs(), util.TestLogger(t))
	require.NoError(t, err)
	require.NotEmpty(t, cs)
	legacy := hostileResults()
	type fixture struct {
		valid, header, line string
		success             float64
	}
	const conntrackHeader = "entries searched found new invalid ignore delete delete_list insert insert_failed drop early_drop icmp_error expect_new expect_create expect_delete search_restart\n"
	const conntrackRow = "1 0 1 0 1 1 0 0 1 1 1 1 0 0 0 0 1\n"
	const udpHeader = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
	const udpRow = "0: 00000000:0016 00000000:0000 0A 00000015:00000002 00:00000000 00000000 0 0 2740 1 ffff88003d3af3c0 100\n"
	const ipvsHeader = "IP Virtual Server version 1.2.1 (size=4096)\nProt LocalAddress:Port Scheduler Flags\n  -> RemoteAddress:Port Forward Weight ActiveConn InActConn\nTCP 7F000001:0050 rr\n"
	const ipvsBackend = "  -> 7F000002:0050 Masq 1 2 3\n"
	const psi = "some avg10=0 avg60=0 avg300=0 total=1\nfull avg10=0 avg60=0 avg300=0 total=1\n"
	fixtures := map[string]fixture{
		"file:/proc/stat":                                 {valid: "cpu 0 0 0 0\ncpu0 1\n"},
		"file:/proc/diskstats":                            {valid: "1 1 d0 0 0 0 0 0 0 0 0 0 0 0\n"},
		"file:/proc/net/dev":                              {valid: "Inter-|\nface |\nn0:0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"},
		"file:/proc/meminfo":                              {valid: "MemTotal: 1 kB\n"},
		"file:/proc/self/mounts":                          {valid: "x /m0 e rw 0 0\n"},
		"cmd:env LC_ALL=C df -akPT":                       {valid: "Filesystem\nx e 1 0 1 0% /m0\n"},
		"cmd:env LC_ALL=C df -aiPT":                       {valid: "Filesystem\nx e 1 0 1 0% /m0\n"},
		"file:/proc/sys/net/netfilter/nf_conntrack_count": {"1\n", "1\n", "\n", 1},
		"file:/proc/sys/net/netfilter/nf_conntrack_max":   {"2\n", "2\n", "\n", 1},
		"file:/proc/net/stat/nf_conntrack":                {conntrackHeader + conntrackRow, conntrackHeader, conntrackRow, 1},
		"file:/proc/sys/kernel/random/entropy_avail":      {"1\n", "1\n", "\n", 1},
		"file:/proc/sys/kernel/random/poolsize":           {"2\n", "2\n", "\n", 1},
		"file:/proc/sys/fs/file-nr":                       {"1 0 2\n", "1 0 2\n", "\n", 1},
		"file:/proc/net/rpc/nfs":                          {"net 1 2 3 4\nrpc 1 2 3\n", "", "rpc 1 2 3\n", 0},
		"file:/proc/net/ip_vs":                            {ipvsHeader + ipvsBackend, ipvsHeader, ipvsBackend, 0},
		"file:/proc/net/ip_vs_stats":                      {"Total\nConns InPkts OutPkts InBytes OutBytes\n1 2 3 4 5\n\n", "Total\nConns InPkts OutPkts InBytes OutBytes\n1 2 3 4 5\n\n", "1 2 3 4 5\n", 1},
		"file:/proc/loadavg":                              {"0 0 0 1/1 1\n", "0 0 0 1/1 1\n", "\n", 1},
		"file:/proc/mdstat":                               {"Personalities : [raid1]\nmd0 : active raid1 sda[0]\n 1 blocks [1/1] [U]\n", "Personalities : [raid1]\n", "md%d : active raid1 sda[0]\n 1 blocks [1/1] [U]\n", 0},
		"file:/proc/net/snmp":                             {"Tcp: InErrs\nTcp: 1\n", "", "P%d: InErrors\nP%d: 1\n", 0},
		"file:/proc/net/snmp6":                            {"Ip6InOctets 1\n", "", "Ip6X%dInErrors 1\n", 0},
		"file:/proc/net/netstat":                          {"TcpExt: ListenDrops\nTcpExt: 1\n", "", "P%d: InErrors\nP%d: 1\n", 0},
		"file:/etc/os-release":                            {"NAME=Linux\nID=linux\n", "NAME=Linux\nID=linux\n", "X%d=1\n", 1},
		"file:/usr/lib/os-release":                        {"NAME=Linux\nID=linux\n", "NAME=Linux\nID=linux\n", "X%d=1\n", 1},
		"file:/proc/pressure/cpu":                         {psi, "", psi, 0},
		"file:/proc/pressure/memory":                      {psi, "", psi, 0},
		"file:/proc/pressure/io":                          {psi, "", psi, 0},
		"file:/proc/pressure/irq":                         {psi, "", psi, 0},
		"file:/proc/schedstat":                            {"version 15\ncpu0 0 0 0 0 0 0 1 1 1\n", "version 15\n", "cpu%d 0 0 0 0 0 0 1 1 1\n", 0},
		"file:/proc/net/sockstat":                         {"sockets: used 1\nTCP: inuse 1\n", "", "P%d: inuse 1\n", 0},
		"file:/proc/net/sockstat6":                        {"TCP6: inuse 1\n", "", "P%d: inuse 1\n", 0},
		"cmd:getconf PAGESIZE":                            {"4096\n", "4096\n", "\n", 1},
		"file:/proc/net/softnet_stat":                     {"0 0 0 0 0 0 0 0 0\n", "", "0 0 0 0 0 0 0 0 0\n", 0},
		"file:/proc/net/udp":                              {udpHeader + udpRow, udpHeader, udpRow, 1},
		"file:/proc/net/udp6":                             {udpHeader + udpRow, udpHeader, udpRow, 1},
		"cmd:uname -s":                                    {"Linux\n", "", "Linux\n", 0},
		"cmd:uname -n":                                    {"host\n", "", "host\n", 0},
		"cmd:uname -r":                                    {"6.1\n", "", "6.1\n", 0},
		"cmd:uname -v":                                    {"version\n", "", "version\n", 0},
		"cmd:uname -m":                                    {"x86_64\n", "", "x86_64\n", 0},
		"file:/proc/sys/kernel/domainname":                {"domain\n", "", "domain\n", 0},
		"file:/proc/vmstat":                               {"pgfault 1\n", "", "pgfault%d 1\n", 0},
	}
	// Fourth-wave defaults: add fixed-read cases without changing the existing corpus.
	fixtures["file:/proc/net/rpc/nfsd"] = fixture{"rc 0 0 1\n", "", "rc 0 0 1\n", 0}
	fixtures["file:/proc/net/arp"] = fixture{"192.0.2.1 0x1 0x2 00:11:22:33:44:55 * eth0\n", "", "192.0.2.1 0x1 0x2 00:11:22:33:44:55 * eth0\n", 1}
	for _, attribute := range []string{
		"bios_date", "bios_release", "bios_vendor", "bios_version",
		"board_asset_tag", "board_name", "board_serial", "board_vendor", "board_version",
		"chassis_asset_tag", "chassis_serial", "chassis_vendor", "chassis_version",
		"product_family", "product_name", "product_serial", "product_sku", "product_uuid", "product_version", "sys_vendor",
	} {
		fixtures["file:/sys/class/dmi/id/"+attribute] = fixture{"vendor\n", "", "vendor\n", 0}
	}
	// Fifth-wave fixed reads keep earlier fixtures and caps unchanged.
	fixtures["file:/proc/self/mountinfo"] = fixture{"22 18 0:19 / /sys/fs/selinux rw - selinuxfs selinuxfs rw\n", "", "22 18 0:19 / /sys/fs/selinux rw - selinuxfs selinuxfs rw\n", 1}
	fixtures["file:/sys/fs/selinux/enforce"] = fixture{"1\n", "1\n", "\n", 0}
	fixtures["file:/etc/selinux/config"] = fixture{"SELINUX=enforcing\n", "SELINUX=enforcing\n", "# comment\n", 0}
	for _, file := range []string{"abdstats", "arcstats", "dbufstats", "dmu_tx", "dnodestats", "fm", "vdev_cache_stats", "vdev_mirror_stats", "xuio_stats", "zfetchstats", "zil"} {
		fixtures["file:/proc/spl/kstat/zfs/"+file] = fixture{"name type data\nvalue 4 1\n", "name type data\n", "value%d 4 1\n", 0}
	}
	fill := func(f fixture) []byte {
		var b strings.Builder
		b.WriteString(f.header)
		for i := 0; ; i++ {
			line := f.line
			if strings.Contains(line, "%d") {
				// The paired netstat header/value rows use the same protocol.
				line = strings.ReplaceAll(line, "%d", fmt.Sprint(i))
			}
			if b.Len()+len(line) > (1<<20)-1 {
				break
			}
			b.WriteString(line)
		}
		return []byte(b.String())
	}
	for _, collector := range cs {
		if _, ok := hostileStorageCases[collector.Name()]; ok {
			t.Run(collector.Name(), func(t *testing.T) { hostileStorageExpanded(t, collector) })
			continue
		}
		// Expanded attributes need their own two-phase proof; the existing
		// fixed-read corpus below intentionally still requires one runner call.
		switch collector.Name() {
		case "thermal_zone", "cpufreq", "bonding", "powersupplyclass", "nvme", "edac":
			t.Run(collector.Name(), func(t *testing.T) { hostileHardwareExpanded(t, collector) })
			continue
		}
		if collector.Name() == "netclass" {
			t.Run(collector.Name(), func(t *testing.T) { hostileNetclassExpanded(t, collector) })
			continue
		}
		t.Run(collector.Name(), func(t *testing.T) {
			reads := collector.Reads()
			require.NotEmpty(t, reads)
			// A successful ordinary snapshot proves that a hostile later read
			// is not masked by malformed fixtures for earlier reads.
			for hostileIndex := -1; hostileIndex < len(reads); hostileIndex++ {
				name := "baseline"
				if hostileIndex >= 0 {
					name = fmt.Sprintf("read_%d", hostileIndex)
				}
				t.Run(name, func(t *testing.T) {
					results := make(map[string]agentless.Result, len(reads))
					for _, read := range reads {
						f, ok := fixtures[read.ID]
						require.True(t, ok, "missing fixture for default %s read %s", collector.Name(), read.ID)
						results[read.ID] = agentless.Result{Read: read, Output: []byte(f.valid)}
					}
					readID, inputBytes, wantSuccess := "baseline", 0, 1.0
					if hostileIndex >= 0 {
						hostileRead := reads[hostileIndex]
						f := fixtures[hostileRead.ID]
						var output []byte
						if res, ok := legacy[hostileRead.ID]; ok {
							output = res.Output
						} else {
							require.NotEmpty(t, f.line, "missing hostile fixture for %s", hostileRead.ID)
							output = fill(f)
						}
						require.Greater(t, len(output), 1000000, "exercise a nearly 1-MiB fixed read")
						require.Less(t, len(output), 1<<20)
						results[hostileRead.ID] = agentless.Result{Read: hostileRead, Output: output}
						readID, inputBytes, wantSuccess = hostileRead.ID, len(output), f.success
						if hostileRead.ID == "file:/usr/lib/os-release" {
							read := agentless.FileRead("/etc/os-release")
							results[read.ID] = agentless.Result{Read: read, NotExist: true, ExitStatus: 1}
						}
					}
					runner := &agentlesstest.FakeRunner{Results: results}
					s, err := agentless.NewScraper(runner, []agentless.Collector{collector}, util.TestLogger(t))
					require.NoError(t, err)
					require.Equal(t, reads, s.Reads())
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
					series, dataFamilies, successMetrics, durationMetrics := 0, 0, 0, 0
					for _, family := range families {
						switch family.GetName() {
						case "node_scrape_collector_success":
							successMetrics += len(family.Metric)
							require.Len(t, family.Metric, 1)
							require.Equal(t, wantSuccess, family.Metric[0].GetGauge().GetValue(), "read %s", readID)
						case "node_scrape_collector_duration_seconds":
							durationMetrics += len(family.Metric)
						default:
							dataFamilies++
							series += len(family.Metric)
						}
						for _, metric := range family.Metric {
							for _, label := range metric.Label {
								require.LessOrEqual(t, len(label.GetValue()), 4096, "label cap for %s", family.GetName())
							}
						}
					}
					require.Equal(t, 1, runner.Calls())
					require.Equal(t, 1, successMetrics)
					require.Equal(t, 1, durationMetrics)
					if wantSuccess == 1 {
						require.Positive(t, series, "successful default must export data, not just scrape status")
					}
					require.LessOrEqual(t, series, 20000)
					require.LessOrEqual(t, dataFamilies, 500)
					t.Logf("collector=%s read=%s input=%d families=%d series=%d elapsed=%s total_alloc=%d heap_in_use=%d baseline=%d sampled_peak=%d", collector.Name(), readID, inputBytes, dataFamilies, series, time.Since(start), after.TotalAlloc-before.TotalAlloc, after.HeapInuse, before.HeapInuse, peak.Load())
					require.Less(t, peak.Load(), uint64(64<<20), "hostile processing must stay below 64 MiB of sampled heap")
					require.Less(t, after.HeapInuse, uint64(64<<20), "hostile default-collector Gather must use less than 64 MiB of heap")
					runtime.KeepAlive(collector)
					runtime.KeepAlive(families)
				})
			}
		})
	}
}

// Unlike FakeRunner, this inventory never turns an unknown read into an
// optional missing file. Each fixture belongs to exactly one execution phase.
type hostileAggregateRunner struct {
	inventory [3]map[string]agentless.Result
	batches   [][]agentless.Read
	input     agentless.Input
}

func (r *hostileAggregateRunner) Run(_ context.Context, _ agentless.Target, reads []agentless.Read) ([]agentless.Result, error) {
	phase := len(r.batches)
	r.batches = append(r.batches, append([]agentless.Read(nil), reads...))
	if phase >= len(r.inventory) {
		return nil, fmt.Errorf("unexpected aggregate phase %d", phase+1)
	}
	results := make([]agentless.Result, 0, len(reads))
	for _, read := range reads {
		result, ok := r.inventory[phase][read.ID]
		if !ok {
			return nil, fmt.Errorf("unrecorded aggregate read in phase %d: %s", phase+1, read.ID)
		}
		if read.Path != result.Read.Path || strings.Join(read.Argv, "\x00") != strings.Join(result.Read.Argv, "\x00") {
			return nil, fmt.Errorf("aggregate read identity mismatch: %s", read.ID)
		}
		if _, duplicate := r.input[read.ID]; duplicate {
			return nil, fmt.Errorf("duplicate aggregate read: %s", read.ID)
		}
		results = append(results, result)
		r.input[read.ID] = result
	}
	return results, nil
}

func TestHostileAggregateRunnerRejectsUnknown(t *testing.T) {
	r := &hostileAggregateRunner{input: agentless.Input{}}
	results, err := r.Run(t.Context(), agentless.Target{}, []agentless.Read{agentless.FileRead("/unknown")})
	require.ErrorContains(t, err, "unrecorded aggregate read in phase 1")
	require.Nil(t, results)
	require.Empty(t, r.input)
}

func hostileAggregateInventory() [3]map[string]agentless.Result {
	inventory := [3]map[string]agentless.Result{hostileResults(), {}, {}}
	put := func(phase int, read agentless.Read, value string) {
		inventory[phase][read.ID] = agentless.Result{Read: read, Output: []byte(value)}
	}
	const psi = "some avg10=0 avg60=0 avg300=0 total=1\nfull avg10=0 avg60=0 avg300=0 total=1\n"
	const udp = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n0: 00000000:0016 00000000:0000 0A 00000015:00000002 00:00000000 00000000 0 0 2740 1 ffff88003d3af3c0 100\n"
	// Ordinary supporting reads, not another simultaneous hostile corpus.
	for path, value := range map[string]string{
		"/proc/sys/net/netfilter/nf_conntrack_count": "1\n",
		"/proc/sys/net/netfilter/nf_conntrack_max":   "2\n",
		"/proc/net/stat/nf_conntrack":                "entries searched found new invalid ignore delete delete_list insert insert_failed drop early_drop icmp_error expect_new expect_create expect_delete search_restart\n1 0 1 0 1 1 0 0 1 1 1 1 0 0 0 0 1\n",
		"/proc/sys/kernel/random/entropy_avail":      "1\n",
		"/proc/sys/kernel/random/poolsize":           "2\n",
		"/proc/sys/fs/file-nr":                       "1 0 2\n",
		"/proc/net/rpc/nfs":                          "net 1 2 3 4\nrpc 1 2 3\n",
		"/proc/net/rpc/nfsd":                         "rc 0 0 1\n",
		"/proc/net/ip_vs":                            "IP Virtual Server version 1.2.1 (size=4096)\nProt LocalAddress:Port Scheduler Flags\n  -> RemoteAddress:Port Forward Weight ActiveConn InActConn\nTCP 7F000001:0050 rr\n  -> 7F000002:0050 Masq 1 2 3\n",
		"/proc/net/ip_vs_stats":                      "Total\nConns InPkts OutPkts InBytes OutBytes\n1 2 3 4 5\n\n",
		"/proc/loadavg":                              "0 0 0 1/1 1\n",
		"/proc/mdstat":                               "Personalities : [raid1]\nmd0 : active raid1 sda[0]\n 1 blocks [1/1] [U]\n",
		"/proc/net/snmp":                             "Tcp: InErrs\nTcp: 1\n",
		"/proc/net/snmp6":                            "Ip6InOctets 1\n",
		"/proc/net/netstat":                          "TcpExt: ListenDrops\nTcpExt: 1\n",
		"/etc/os-release":                            "NAME=Linux\nID=linux\n",
		"/usr/lib/os-release":                        "NAME=Linux\nID=linux\n",
		"/proc/pressure/cpu":                         psi,
		"/proc/pressure/memory":                      psi,
		"/proc/pressure/io":                          psi,
		"/proc/pressure/irq":                         psi,
		"/proc/schedstat":                            "version 15\ncpu0 0 0 0 0 0 0 1 1 1\n",
		"/proc/net/sockstat":                         "sockets: used 1\nTCP: inuse 1\n",
		"/proc/net/sockstat6":                        "TCP6: inuse 1\n",
		"/proc/net/softnet_stat":                     "0 0 0 0 0 0 0 0 0\n",
		"/proc/net/udp":                              udp,
		"/proc/net/udp6":                             udp,
		"/proc/sys/kernel/domainname":                "domain\n",
		"/proc/vmstat":                               "pgfault 1\n",
		"/proc/net/arp":                              "192.0.2.1 0x1 0x2 00:11:22:33:44:55 * eth0\n",
		"/proc/self/mountinfo":                       "22 18 0:19 / /sys/fs/selinux rw - selinuxfs selinuxfs rw\n",
		"/sys/fs/selinux/enforce":                    "1\n",
		"/etc/selinux/config":                        "SELINUX=enforcing\n",
		"/sys/class/net/bonding_masters":             "bond0\n",
	} {
		put(0, agentless.FileRead(path), value)
	}
	for _, attribute := range []string{
		"bios_date", "bios_release", "bios_vendor", "bios_version", "board_asset_tag", "board_name", "board_serial", "board_vendor", "board_version", "chassis_asset_tag", "chassis_serial", "chassis_vendor", "chassis_version", "product_family", "product_name", "product_serial", "product_sku", "product_uuid", "product_version", "sys_vendor",
	} {
		put(0, agentless.FileRead("/sys/class/dmi/id/"+attribute), "vendor\n")
	}
	for _, file := range []string{"abdstats", "arcstats", "dbufstats", "dmu_tx", "dnodestats", "fm", "vdev_cache_stats", "vdev_mirror_stats", "xuio_stats", "zfetchstats", "zil"} {
		put(0, agentless.FileRead("/proc/spl/kstat/zfs/"+file), "name type data\nvalue 4 1\n")
	}
	put(0, agentless.CommandRead("getconf", "PAGESIZE"), "4096\n")
	for flag, value := range map[string]string{"-s": "Linux\n", "-n": "host\n", "-r": "6.1\n", "-v": "version\n", "-m": "x86_64\n"} {
		put(0, agentless.CommandRead("uname", flag), value)
	}
	for path, value := range map[string]string{
		"/sys/class/net":              "bond0\nbonding_masters\neth0\n",
		"/sys/class/thermal":          "thermal_zone0\n",
		"/sys/devices/system/cpu":     "cpu0\n",
		"/sys/class/power_supply":     "BAT0\n",
		"/sys/class/nvme":             "nvme0\n",
		"/sys/devices/system/edac/mc": "mc0\n",
		"/sys/class/fc_host":          "host0\n",
		"/sys/class/scsi_tape":        "st0\n",
		"/sys/fs/btrfs":               "11111111-1111-1111-1111-111111111111\n",
	} {
		put(0, agentless.CommandRead("ls", "-1", path), value)
	}
	for _, device := range []string{"bond0", "eth0"} {
		for _, attribute := range []string{"addr_assign_type", "carrier", "carrier_changes", "carrier_up_count", "carrier_down_count", "dev_id", "dormant", "flags", "ifindex", "iflink", "link_mode", "mtu", "name_assign_type", "netdev_group", "speed", "tx_queue_len", "type", "address", "broadcast", "duplex", "operstate", "ifalias"} {
			value := "1\n"
			if attribute == "operstate" {
				value = "up\n"
			}
			put(1, agentless.FileRead("/sys/class/net/"+device+"/"+attribute), value)
		}
		put(1, agentless.FileRead("/sys/class/net/"+device+"/bonding_slave/mii_status"), "up\n")
	}
	put(1, agentless.FileRead("/sys/class/net/bond0/bonding/slaves"), "eth0\n")
	for attribute, value := range map[string]string{"type": "x86_pkg_temp\n", "temp": "42000\n", "policy": "step_wise\n", "mode": "enabled\n"} {
		put(1, agentless.FileRead("/sys/class/thermal/thermal_zone0/"+attribute), value)
	}
	for _, attribute := range []string{"cpuinfo_cur_freq", "cpuinfo_min_freq", "cpuinfo_max_freq", "scaling_cur_freq", "scaling_min_freq", "scaling_max_freq"} {
		put(1, agentless.FileRead("/sys/devices/system/cpu/cpu0/cpufreq/"+attribute), "1000000\n")
	}
	put(1, agentless.FileRead("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"), "performance\n")
	put(1, agentless.FileRead("/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors"), "performance powersave\n")
	for _, attribute := range []string{
		"authentic", "calibrate", "capacity", "capacity_alert_max", "capacity_alert_min", "cycle_count", "online", "present", "time_to_empty_now", "time_to_full_now", "current_boot", "current_max", "current_now", "energy_empty", "energy_empty_design", "energy_full", "energy_full_design", "energy_now", "voltage_boot", "voltage_max", "voltage_max_design", "voltage_min", "voltage_min_design", "voltage_now", "voltage_ocv", "charge_control_limit", "charge_control_limit_max", "charge_counter", "charge_empty", "charge_empty_design", "charge_full", "charge_full_design", "charge_now", "charge_term_current", "constant_charge_current", "constant_charge_current_max", "constant_charge_voltage", "constant_charge_voltage_max", "precharge_current", "input_current_limit", "power_now", "temp", "temp_alert_max", "temp_alert_min", "temp_ambient", "temp_ambient_max", "temp_ambient_min", "temp_max", "temp_min",
	} {
		put(1, agentless.FileRead("/sys/class/power_supply/BAT0/"+attribute), "1000000\n")
	}
	for _, attribute := range []string{"capacity_level", "charge_type", "health", "manufacturer", "model_name", "serial_number", "status", "technology", "type", "usb_type", "scope"} {
		put(1, agentless.FileRead("/sys/class/power_supply/BAT0/"+attribute), "ordinary\n")
	}
	for attribute, value := range map[string]string{"firmware_rev": "1.0\n", "model": "ordinary\n", "serial": "fixture\n", "state": "live\n", "cntlid": "1\n"} {
		put(1, agentless.FileRead("/sys/class/nvme/nvme0/"+attribute), value)
	}
	put(1, agentless.CommandRead("ls", "-1", "/sys/devices/system/edac/mc/mc0"), "csrow0\n")
	for _, attribute := range []string{"ce_count", "ce_noinfo_count", "ue_count", "ue_noinfo_count"} {
		put(1, agentless.FileRead("/sys/devices/system/edac/mc/mc0/"+attribute), "1\n")
	}
	for _, attribute := range []string{"ce_count", "ue_count"} {
		put(2, agentless.FileRead("/sys/devices/system/edac/mc/mc0/csrow0/"+attribute), "2\n")
	}
	for _, attribute := range []string{"speed", "port_state", "port_type", "port_id", "port_name", "fabric_name", "symbolic_name", "supported_classes", "supported_speeds", "dev_loss_tmo", "node_name"} {
		put(1, agentless.FileRead("/sys/class/fc_host/host0/"+attribute), "0x01\n")
	}
	for _, attribute := range []string{"dumped_frames", "error_frames", "invalid_crc_count", "rx_frames", "rx_words", "tx_frames", "tx_words", "seconds_since_last_reset", "invalid_tx_word_count", "link_failure_count", "loss_of_sync_count", "loss_of_signal_count", "nos_count", "fcp_packet_aborts"} {
		put(1, agentless.FileRead("/sys/class/fc_host/host0/statistics/"+attribute), "1\n")
	}
	for _, attribute := range []string{"in_flight", "io_ns", "other_cnt", "read_byte_cnt", "read_cnt", "read_ns", "resid_cnt", "write_byte_cnt", "write_cnt", "write_ns"} {
		put(1, agentless.FileRead("/sys/class/scsi_tape/st0/stats/"+attribute), "1\n")
	}
	const fs = "/sys/fs/btrfs/11111111-1111-1111-1111-111111111111"
	put(1, agentless.CommandRead("ls", "-1", fs+"/devices"), "sda\n")
	put(1, agentless.FileRead(fs+"/label"), "fixture\n")
	put(1, agentless.FileRead(fs+"/metadata_uuid"), "11111111-1111-1111-1111-111111111111\n")
	put(1, agentless.FileRead(fs+"/allocation/global_rsv_size"), "1\n")
	put(2, agentless.FileRead(fs+"/devices/sda/size"), "1\n")
	for _, group := range []string{"data", "metadata", "system"} {
		put(1, agentless.CommandRead("ls", "-1", fs+"/allocation/"+group), "single\n")
		put(1, agentless.FileRead(fs+"/allocation/"+group+"/bytes_reserved"), "1\n")
		for _, attribute := range []string{"used_bytes", "total_bytes"} {
			put(2, agentless.FileRead(fs+"/allocation/"+group+"/single/"+attribute), "1\n")
		}
	}
	// The three additional defaults use the same ordinary one-device data
	// as hostileStorageExpanded: no multiplied devices or hostile padding.
	const cache = "/sys/fs/bcache/11111111-1111-1111-1111-111111111111"
	put(0, agentless.CommandRead("ls", "-1", "/sys/fs/bcache"), "11111111-1111-1111-1111-111111111111\n")
	put(1, agentless.CommandRead("ls", "-1", cache), "bdev0\ncache0\n")
	for _, attribute := range []string{
		"average_key_size", "btree_cache_size", "cache_available_percent", "congested", "root_usage_percent", "tree_depth", "internal/active_journal_entries", "internal/btree_nodes", "internal/btree_read_average_duration_us", "internal/cache_read_races",
	} {
		put(1, agentless.FileRead(cache+"/"+attribute), "1\n")
	}
	for _, attribute := range []string{
		"dirty_data", "stats_total/bypassed", "stats_total/cache_hits", "stats_total/cache_misses", "stats_total/cache_bypass_hits", "stats_total/cache_bypass_misses", "stats_total/cache_miss_collisions", "stats_total/cache_readaheads",
	} {
		put(2, agentless.FileRead(cache+"/bdev0/"+attribute), "1\n")
	}
	put(2, agentless.FileRead(cache+"/bdev0/writeback_rate_debug"), "target: 1\nrate: 1/sec\nproportional: 1\nintegral: 1\nchange: 1\n")
	for _, attribute := range []string{"io_errors", "metadata_written", "written"} {
		put(2, agentless.FileRead(cache+"/cache0/"+attribute), "1\n")
	}
	put(0, agentless.CommandRead("ls", "-1", "/sys/class/infiniband"), "mlx4_0\n")
	const ib = "/sys/class/infiniband/mlx4_0"
	put(1, agentless.CommandRead("ls", "-1", ib+"/ports"), "1\n")
	for _, attribute := range []string{"board_id", "fw_ver", "hca_type"} {
		put(1, agentless.FileRead(ib+"/"+attribute), "1\n")
	}
	for _, attribute := range []string{
		"counters_ext/port_multicast_rcv_packets", "counters_ext/port_multicast_xmit_packets", "counters_ext/port_rcv_data_64", "counters_ext/port_rcv_packets_64", "counters_ext/port_unicast_rcv_packets", "counters_ext/port_unicast_xmit_packets", "counters_ext/port_xmit_data_64", "counters_ext/port_xmit_packets_64",
		"counters/link_downed", "counters/link_error_recovery", "counters/multicast_rcv_packets", "counters/multicast_xmit_packets", "counters/port_rcv_constraint_errors", "counters/port_xmit_constraint_errors", "counters/port_rcv_data", "counters/port_xmit_data", "counters/port_rcv_discards", "counters/port_xmit_discards", "counters/port_rcv_errors", "counters/port_rcv_packets", "counters/port_xmit_packets", "counters/port_xmit_wait", "counters/unicast_rcv_packets", "counters/unicast_xmit_packets",
	} {
		put(2, agentless.FileRead(ib+"/ports/1/"+attribute), "1\n")
	}
	for attribute, value := range map[string]string{"state": "4: ACTIVE\n", "phys_state": "5: LinkUp\n", "rate": "40 Gb/sec\n"} {
		put(2, agentless.FileRead(ib+"/ports/1/"+attribute), value)
	}
	put(0, agentless.CommandRead("ls", "-1", "/sys/fs/xfs"), "sda1\n")
	put(1, agentless.FileRead("/sys/fs/xfs/sda1/stats/stats"), "rw 1 2\n")
	return inventory
}

// Family ownership is explicit, independent of the production buffer and its
// limits. Overlapping CPU/network namespaces are disambiguated before prefixes.
func hostileAggregateFamilyOwner(name string) string {
	switch name {
	case "node_cpu_seconds_total", "node_cpu_guest_seconds_total":
		return "cpu"
	case "node_intr_total", "node_context_switches_total", "node_forks_total", "node_boot_time_seconds", "node_procs_running", "node_procs_blocked":
		return "stat"
	case "node_entropy_available_bits", "node_entropy_pool_size_bits":
		return "entropy"
	case "node_udp_queues":
		return "udp_queues"
	}
	if strings.HasSuffix(name, "_total") && (strings.HasPrefix(name, "node_network_receive_") || strings.HasPrefix(name, "node_network_transmit_")) {
		return "netdev"
	}
	prefixes := map[string]string{
		"arp": "node_arp_", "bonding": "node_bonding_", "btrfs": "node_btrfs_", "fibrechannel": "node_fibrechannel_", "tapestats": "node_tape_", "conntrack": "node_nf_conntrack_", "cpufreq": "node_cpu_", "diskstats": "node_disk_", "dmi": "node_dmi_", "edac": "node_edac_", "filefd": "node_filefd_", "filesystem": "node_filesystem_", "ipvs": "node_ipvs_", "loadavg": "node_load", "mdadm": "node_md_", "meminfo": "node_memory_", "netclass": "node_network_", "netstat": "node_netstat_", "nfs": "node_nfs_", "nfsd": "node_nfsd_", "nvme": "node_nvme_", "os": "node_os_", "powersupplyclass": "node_power_supply_", "pressure": "node_pressure_", "schedstat": "node_schedstat_", "selinux": "node_selinux_", "sockstat": "node_sockstat_", "softnet": "node_softnet_", "thermal_zone": "node_thermal_zone_", "uname": "node_uname_", "vmstat": "node_vmstat_", "zfs": "node_zfs_",
	}
	prefixes["bcache"] = "node_bcache_"
	prefixes["infiniband"] = "node_infiniband_"
	prefixes["xfs"] = "node_xfs_"
	for owner, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			return owner
		}
	}
	return ""
}

// ONE result, registry and Gather for the original seven hostile sections plus
// ordinary successful support for every other default, including real EDAC
// phase three. The corpus and all legitimate owners stay live throughout.
func TestHostileAllDefaultsAggregateHeap(t *testing.T) {
	names := collectors.DefaultEnabled()
	require.Equal(t, strings.Fields("arp bcache bonding btrfs conntrack cpu cpufreq diskstats dmi edac entropy fibrechannel filefd filesystem infiniband ipvs loadavg mdadm meminfo netclass netdev netstat nfs nfsd nvme os powersupplyclass pressure schedstat selinux sockstat softnet stat tapestats thermal_zone udp_queues uname vmstat xfs zfs"), names)
	cs, err := collectors.Build(names, collectors.DefaultConfigs(), util.TestLogger(t))
	require.NoError(t, err)
	runner := &hostileAggregateRunner{inventory: hostileAggregateInventory(), input: agentless.Input{}}
	logical, unique := 0, 0
	backings := map[*byte]bool{}
	for _, phase := range runner.inventory {
		for _, result := range phase {
			logical += len(result.Output)
			if len(result.Output) != 0 && !backings[&result.Output[0]] {
				unique += len(result.Output)
				backings[&result.Output[0]] = true
			}
		}
	}
	require.Greater(t, logical, 7300000)
	dfBlocks := runner.inventory[0][agentless.CommandRead("env", "LC_ALL=C", "df", "-akPT").ID].Output
	dfInodes := runner.inventory[0][agentless.CommandRead("env", "LC_ALL=C", "df", "-aiPT").ID].Output
	require.True(t, &dfBlocks[0] == &dfInodes[0], "preserve original df backing alias")
	s, err := agentless.NewScraper(runner, cs, util.TestLogger(t))
	require.NoError(t, err)
	reg := prometheus.NewRegistry()
	runtime.GC() // Initial fixture setup only; no forced GC in measured work.
	var before, after, postGC runtime.MemStats
	runtime.ReadMemStats(&before)
	var peak atomic.Uint64
	peak.Store(before.HeapInuse)
	stop, done, ready := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		var sample runtime.MemStats
		runtime.ReadMemStats(&sample)
		if sample.HeapInuse > peak.Load() {
			peak.Store(sample.HeapInuse)
		}
		close(ready)
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				runtime.ReadMemStats(&sample)
				if sample.HeapInuse > peak.Load() {
					peak.Store(sample.HeapInuse)
				}
			}
		}
	}()
	stopSampler := sync.OnceFunc(func() { close(stop); <-done })
	t.Cleanup(stopSampler)
	<-ready
	start := time.Now()
	result, err := s.Scrape(t.Context(), agentless.Target{Address: "host:22", Auth: "default"})
	require.NoError(t, err)
	require.NoError(t, reg.Register(result))
	families, err := reg.Gather()
	runtime.ReadMemStats(&after) // Immediate after-Gather, before assertions/teardown.
	stopSampler()
	if after.HeapInuse > peak.Load() {
		peak.Store(after.HeapInuse)
	}
	require.NoError(t, err)
	// The two existing bounds measure unforced-GC work. The post-GC bound
	// checks retained heap with all legitimate owners live past the snapshot.
	runtime.GC()
	runtime.ReadMemStats(&postGC)
	t.Logf("defaults=%d logical_input=%d unique_input=%d baseline=%d sampled_peak=%d after_gather=%d post_gc=%d total_alloc=%d allocations=%d gc=%d elapsed=%s families=%d", len(cs), logical, unique, before.HeapInuse, peak.Load(), after.HeapInuse, postGC.HeapInuse, after.TotalAlloc-before.TotalAlloc, after.Mallocs-before.Mallocs, after.NumGC-before.NumGC, time.Since(start), len(families))
	// Validate exact executed identities/phases, including deduped shared reads.
	require.Len(t, runner.batches, 3)
	require.Equal(t, s.Reads(), runner.batches[0])
	for phase, batch := range runner.batches {
		require.Len(t, batch, len(runner.inventory[phase]))
		for _, read := range batch {
			require.NoError(t, read.Validate())
			require.Equal(t, runner.inventory[phase][read.ID].Read, read)
		}
	}
	require.Len(t, runner.batches[2], 48)
	require.Len(t, runner.input, len(runner.inventory[0])+len(runner.inventory[1])+len(runner.inventory[2]))
	failed := map[string]bool{"cpu": true, "diskstats": true, "filesystem": true, "meminfo": true, "netdev": true, "stat": true}
	statusCounts, durationCounts, series, familyCounts := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	byFamily := map[string]int{}
	for _, family := range families {
		name := family.GetName()
		if name != "node_scrape_collector_success" && name != "node_scrape_collector_duration_seconds" {
			owner := hostileAggregateFamilyOwner(name)
			require.NotEmpty(t, owner, "unowned data family %s", name)
			familyCounts[owner]++
			series[owner] += len(family.Metric)
			byFamily[name] = len(family.Metric)
		}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				require.LessOrEqual(t, len(label.GetValue()), 4096, "%s label %s", name, label.GetName())
			}
			if name == "node_scrape_collector_success" || name == "node_scrape_collector_duration_seconds" {
				require.Len(t, metric.Label, 1)
				require.Equal(t, "collector", metric.Label[0].GetName())
				collector := metric.Label[0].GetValue()
				require.Contains(t, names, collector)
				if name == "node_scrape_collector_success" {
					statusCounts[collector]++
					want := 1.0
					if failed[collector] {
						want = 0
					}
					require.Equal(t, want, metric.GetGauge().GetValue(), collector)
				} else {
					durationCounts[collector]++
				}
			}
		}
	}
	totalSeries := 0
	for _, name := range names {
		require.Equal(t, 1, statusCounts[name], name)
		require.Equal(t, 1, durationCounts[name], name)
		if failed[name] {
			require.Zero(t, series[name], "atomic failure: %s", name)
		} else {
			require.Positive(t, series[name], "ordinary successful data: %s", name)
		}
		require.LessOrEqual(t, series[name], 20000, name)
		require.LessOrEqual(t, familyCounts[name], 500, name)
		totalSeries += series[name]
		t.Logf("collector=%s data_families=%d data_series=%d", name, familyCounts[name], series[name])
	}
	for family, count := range map[string]int{
		"node_bonding_slaves": 1, "node_bonding_active": 1,
		"node_cpu_frequency_hertz": 1, "node_cpu_scaling_governor": 2,
		"node_edac_correctable_errors_total": 1, "node_edac_uncorrectable_errors_total": 1,
		"node_edac_csrow_correctable_errors_total": 2, "node_edac_csrow_uncorrectable_errors_total": 2,
		"node_nvme_info": 1, "node_power_supply_info": 1, "node_power_supply_capacity": 1,
		"node_thermal_zone_temp": 1, "node_network_info": 2,
	} {
		require.Equal(t, count, byFamily[family], "real hardware data: %s", family)
	}
	// Check every newly supported family, not just successful status. The
	// fixture has one FC host, one tape, and one Btrfs filesystem/device with
	// one single-layout allocation in each of the three block groups.
	for family, expected := range map[string]struct {
		count int
		value float64
	}{
		"node_fibrechannel_info":                           {1, 1},
		"node_fibrechannel_dumped_frames_total":            {1, 1},
		"node_fibrechannel_error_frames_total":             {1, 1},
		"node_fibrechannel_invalid_crc_total":              {1, 1},
		"node_fibrechannel_rx_frames_total":                {1, 1},
		"node_fibrechannel_rx_words_total":                 {1, 1},
		"node_fibrechannel_tx_frames_total":                {1, 1},
		"node_fibrechannel_tx_words_total":                 {1, 1},
		"node_fibrechannel_seconds_since_last_reset_total": {1, 1},
		"node_fibrechannel_invalid_tx_words_total":         {1, 1},
		"node_fibrechannel_link_failure_total":             {1, 1},
		"node_fibrechannel_loss_of_sync_total":             {1, 1},
		"node_fibrechannel_loss_of_signal_total":           {1, 1},
		"node_fibrechannel_nos_total":                      {1, 1},
		"node_fibrechannel_fcp_packet_aborts_total":        {1, 1},
		"node_tape_io_now":                                 {1, 1},
		"node_tape_io_time_seconds_total":                  {1, 1e-9},
		"node_tape_io_others_total":                        {1, 1},
		"node_tape_read_bytes_total":                       {1, 1},
		"node_tape_reads_completed_total":                  {1, 1},
		"node_tape_read_time_seconds_total":                {1, 1e-9},
		"node_tape_residual_total":                         {1, 1},
		"node_tape_written_bytes_total":                    {1, 1},
		"node_tape_writes_completed_total":                 {1, 1},
		"node_tape_write_time_seconds_total":               {1, 1e-9},
		"node_btrfs_info":                                  {1, 1},
		"node_btrfs_global_rsv_size_bytes":                 {1, 1},
		"node_btrfs_reserved_bytes":                        {3, 1},
		"node_btrfs_used_bytes":                            {3, 1},
		"node_btrfs_size_bytes":                            {3, 1},
		"node_btrfs_allocation_ratio":                      {3, 1},
		"node_btrfs_device_size_bytes":                     {1, 512},
	} {
		require.Equal(t, expected.count, byFamily[family], family)
		for _, actual := range families {
			if actual.GetName() != family {
				continue
			}
			for _, metric := range actual.Metric {
				value := metric.GetGauge().GetValue()
				if metric.Counter != nil {
					value = metric.Counter.GetValue()
				}
				require.Equal(t, expected.value, value, family)
			}
		}
	}
	// Every family of the additional defaults is checked against the ordinary
	// fixture values, including unit conversions and XFS's absent-row zeros.
	newFamilies := map[string]map[float64]string{
		"bcache": {
			1:    "average_key_size_sectors btree_cache_size_bytes cache_available_percent congested root_usage_percent tree_depth active_journal_entries btree_nodes cache_read_races_total dirty_data_bytes dirty_target_bytes writeback_rate writeback_rate_proportional_term writeback_rate_integral_term writeback_change bypassed_bytes_total cache_hits_total cache_misses_total cache_bypass_hits_total cache_bypass_misses_total cache_miss_collisions_total cache_readaheads_total io_errors metadata_written_bytes_total written_bytes_total",
			1e-9: "btree_read_average_duration_seconds",
		},
		"infiniband": {
			1:   "info legacy_multicast_packets_received_total legacy_multicast_packets_transmitted_total legacy_packets_received_total legacy_unicast_packets_received_total legacy_unicast_packets_transmitted_total legacy_packets_transmitted_total link_downed_total link_error_recovery_total multicast_packets_received_total multicast_packets_transmitted_total port_constraint_errors_received_total port_constraint_errors_transmitted_total port_discards_received_total port_discards_transmitted_total port_errors_received_total port_packets_received_total port_packets_transmitted_total port_transmit_wait_total unicast_packets_received_total unicast_packets_transmitted_total",
			4:   "legacy_data_received_bytes_total legacy_data_transmitted_bytes_total port_data_received_bytes_total port_data_transmitted_bytes_total state_id",
			5:   "physical_state_id",
			5e9: "rate_bytes_per_second",
		},
		"xfs": {
			0: "extent_allocation_extents_allocated_total extent_allocation_blocks_allocated_total extent_allocation_extents_freed_total extent_allocation_blocks_freed_total allocation_btree_lookups_total allocation_btree_compares_total allocation_btree_records_inserted_total allocation_btree_records_deleted_total block_mapping_reads_total block_mapping_writes_total block_mapping_unmaps_total block_mapping_extent_list_insertions_total block_mapping_extent_list_deletions_total block_mapping_extent_list_lookups_total block_mapping_extent_list_compares_total block_map_btree_lookups_total block_map_btree_compares_total block_map_btree_records_inserted_total block_map_btree_records_deleted_total directory_operation_lookup_total directory_operation_create_total directory_operation_remove_total directory_operation_getdents_total inode_operation_attempts_total inode_operation_found_total inode_operation_recycled_total inode_operation_missed_total inode_operation_duplicates_total inode_operation_reclaims_total inode_operation_attribute_changes_total vnode_active_total vnode_allocate_total vnode_get_total vnode_hold_total vnode_release_total vnode_reclaim_total vnode_remove_total",
			1: "write_calls_total",
			2: "read_calls_total",
		},
	}
	for owner, values := range newFamilies {
		expectedFamilies := 0
		for value, suffixes := range values {
			for _, suffix := range strings.Fields(suffixes) {
				name := "node_" + owner + "_" + suffix
				expectedFamilies++
				require.Equal(t, 1, byFamily[name], name)
				for _, family := range families {
					if family.GetName() != name {
						continue
					}
					metric := family.Metric[0]
					actual := metric.GetGauge().GetValue()
					if metric.Counter != nil {
						actual = metric.Counter.GetValue()
					}
					require.Equal(t, value, actual, name)
				}
			}
		}
		require.Equal(t, expectedFamilies, familyCounts[owner], owner)
	}
	require.Equal(t, 26, series["bcache"])
	require.Equal(t, 28, series["infiniband"])
	require.Equal(t, 39, series["xfs"])
	require.Equal(t, 15, series["fibrechannel"])
	require.Equal(t, 10, series["tapestats"])
	require.Equal(t, 15, series["btrfs"])
	t.Logf("data_series=%d status_series=%d duration_series=%d executed_reads=%d", totalSeries, len(statusCounts), len(durationCounts), len(runner.input))
	// Nonfatal assertions preserve both independent heap failures in evidence.
	if peak.Load() >= uint64(64<<20) {
		t.Errorf("sampled peak heap %d must be < %d", peak.Load(), uint64(64<<20))
	}
	if after.HeapInuse >= uint64(64<<20) {
		t.Errorf("immediate after-Gather heap %d must be < %d", after.HeapInuse, uint64(64<<20))
	}
	// Frozen before implementation from five independent positive samples:
	// maximum 12,189,696 bytes plus 4 MiB, without baseline subtraction.
	if postGC.HeapInuse >= uint64(16384000) {
		t.Errorf("after-Gather then GC heap %d must be < %d", postGC.HeapInuse, uint64(16384000))
	}
	runtime.KeepAlive(runner.inventory)
	runtime.KeepAlive(runner.input)
	runtime.KeepAlive(runner)
	runtime.KeepAlive(cs)
	runtime.KeepAlive(s)
	runtime.KeepAlive(result)
	runtime.KeepAlive(reg)
	runtime.KeepAlive(families)
}
