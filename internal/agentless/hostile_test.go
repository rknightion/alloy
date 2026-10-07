//go:build hostile

package agentless_test

import (
	"context"
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
	cases := []string{"baseline", "eleven", "twelve", "invalid_names", "failed_attribute", "hostile_listing"}
	cases = append(cases, attributes...)
	for _, mode := range cases {
		t.Run(mode, func(t *testing.T) {
			listing := collector.Reads()[0]
			count, wantCalls, wantSuccess := 1, 2, 1.0
			if mode == "eleven" {
				count = 11
			}
			if mode == "twelve" {
				count, wantCalls, wantSuccess = 12, 1, 0
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
		// Expanded attributes need their own two-phase proof; the existing
		// fixed-read corpus below intentionally still requires one runner call.
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
