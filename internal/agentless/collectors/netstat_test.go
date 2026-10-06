package collectors

import (
	"fmt"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/grafana/alloy/internal/util"
)

func TestNetstatConformance(t *testing.T) {
	conformance.Check(t, conformance.Case{Collector: &netstatCollector{}, Root: "testdata/netstat", Families: []string{
		"node_netstat_Icmp6_InErrors", "node_netstat_Icmp6_InMsgs", "node_netstat_Icmp6_OutMsgs",
		"node_netstat_Icmp_InErrors", "node_netstat_Icmp_InMsgs", "node_netstat_Icmp_OutMsgs",
		"node_netstat_Ip6_InOctets", "node_netstat_Ip6_OutOctets", "node_netstat_IpExt_InOctets", "node_netstat_IpExt_OutOctets", "node_netstat_Ip_Forwarding",
		"node_netstat_TcpExt_ListenDrops", "node_netstat_TcpExt_ListenOverflows", "node_netstat_TcpExt_SyncookiesFailed", "node_netstat_TcpExt_SyncookiesRecv", "node_netstat_TcpExt_SyncookiesSent", "node_netstat_TcpExt_TCPTimeouts",
		"node_netstat_Tcp_ActiveOpens", "node_netstat_Tcp_CurrEstab", "node_netstat_Tcp_InErrs", "node_netstat_Tcp_InSegs", "node_netstat_Tcp_OutRsts", "node_netstat_Tcp_OutSegs", "node_netstat_Tcp_PassiveOpens", "node_netstat_Tcp_RetransSegs",
		"node_netstat_Udp6_InDatagrams", "node_netstat_Udp6_InErrors", "node_netstat_Udp6_NoPorts", "node_netstat_Udp6_OutDatagrams", "node_netstat_Udp6_RcvbufErrors", "node_netstat_Udp6_SndbufErrors",
		"node_netstat_UdpLite6_InErrors", "node_netstat_UdpLite_InErrors", "node_netstat_Udp_InDatagrams", "node_netstat_Udp_InErrors", "node_netstat_Udp_NoPorts", "node_netstat_Udp_OutDatagrams", "node_netstat_Udp_RcvbufErrors", "node_netstat_Udp_SndbufErrors",
	}})
}

func netstatInput() agentless.Input {
	in := agentless.Input{}
	for _, read := range (&netstatCollector{}).Reads() {
		in[read.ID] = agentless.Result{Read: read, NotExist: true, ExitStatus: 1}
	}
	return in
}

func TestNetstatRegistrationAndReads(t *testing.T) {
	cs, err := Build([]string{"netstat"}, DefaultConfigs(), util.TestLogger(t))
	require.NoError(t, err)
	require.Equal(t, "netstat", cs[0].Name())
	require.NotContains(t, DefaultEnabled(), "netstat")
	for _, r := range Registered() {
		if r.Name == "netstat" {
			require.Equal(t, "linux", r.OS)
		}
	}
	require.Equal(t, []agentless.Read{agentless.FileRead("/proc/net/snmp"), agentless.FileRead("/proc/net/snmp6"), agentless.FileRead("/proc/net/netstat")}, cs[0].Reads())
	for _, read := range cs[0].Reads() {
		require.NoError(t, read.Validate())
		require.Empty(t, read.Argv)
	}
}

func TestNetstatMissingAndReadFailures(t *testing.T) {
	c := &netstatCollector{}
	ch := make(chan prometheus.Metric, 100)
	require.NoError(t, c.Update(agentless.Target{}, netstatInput(), ch))
	require.Empty(t, ch)
	for _, read := range c.Reads() {
		for _, result := range []agentless.Result{{ExitStatus: 2}, {Truncated: true}, {TimedOut: true}, {NotExist: true, TimedOut: true}, {NotExist: true, Truncated: true}} {
			in := netstatInput()
			in[read.ID] = result
			require.Error(t, c.Update(agentless.Target{}, in, ch))
		}
		in := netstatInput()
		delete(in, read.ID)
		require.Error(t, c.Update(agentless.Target{}, in, ch))
	}
	// Missing snmp6 does not suppress valid IPv4 statistics.
	in := netstatInput()
	r := c.Reads()[0]
	in[r.ID] = agentless.Result{Output: []byte("Tcp: ActiveOpens MaxConn\nTcp: 3 -1\n")}
	require.NoError(t, c.Update(agentless.Target{}, in, ch))
	require.Len(t, ch, 1)
}

func TestNetstatRejectsMalformedAtomically(t *testing.T) {
	for _, path := range []string{"/proc/net/snmp", "/proc/net/netstat", "/proc/net/snmp6"} {
		outputs := []string{"", "garbage", strings.Repeat("x", 70000)}
		prefix := "Tcp: ActiveOpens\nTcp: 3\n"
		if path == "/proc/net/snmp6" {
			prefix = "Ip6InOctets 3\n"
			outputs = append(outputs, "Ip6InOctets 1", "Ip6OutOctets nope", "Ip6OutOctets NaN", "Ip6OutOctets +Inf", "Ip6OutOctets 1 extra", "IpOutOctets 2", "Ip6 2", "Ip6Bad-name 2")
		} else {
			outputs = append(outputs, "Tcp: ActiveOpens\nTcp: 1", "Tcp: OutSegs\nUdp: 2", "Tcp: OutSegs\nTcp: 1 2", "Tcp: OutSegs InSegs\nTcp: 1", "Tcp: OutSegs\nTcp: nope", "Tcp: OutSegs\nTcp: NaN", "Tcp: OutSegs\nTcp: +Inf", "Tcp: Bad-name\nTcp: 1", "Tcp: OutSegs")
		}
		for i, output := range outputs {
			t.Run(fmt.Sprintf("%s/%d", path, i), func(t *testing.T) {
				in := netstatInput()
				read := agentless.FileRead(path)
				if output != "" {
					output = prefix + output
				}
				in[read.ID] = agentless.Result{Output: []byte(output)}
				ch := make(chan prometheus.Metric, 100)
				require.Error(t, (&netstatCollector{}).Update(agentless.Target{}, in, ch))
				require.Empty(t, ch)
			})
		}
	}
}

func netstatFieldsInput(fields int, ipv6 bool) agentless.Input {
	in := netstatInput()
	var names, values strings.Builder
	path := "/proc/net/netstat"
	if ipv6 {
		path = "/proc/net/snmp6"
		for i := 0; i < fields; i++ {
			fmt.Fprintf(&names, "Ip6Field%d 1\n", i)
		}
	} else {
		names.WriteString("TcpExt:")
		values.WriteString("TcpExt:")
		for i := 0; i < fields; i++ {
			fmt.Fprintf(&names, " Listen%d", i)
			values.WriteString(" 1")
		}
		names.WriteString("\n")
		names.WriteString(values.String())
		names.WriteString("\n")
	}
	in[agentless.FileRead(path).ID] = agentless.Result{Output: []byte(names.String())}
	return in
}

func TestNetstatPreRetentionBounds(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, fields := range []int{499, 500, 501, 2000} {
			t.Run(fmt.Sprintf("%t/%d", ipv6, fields), func(t *testing.T) {
				ch := make(chan prometheus.Metric, 501)
				err := (&netstatCollector{}).Update(agentless.Target{}, netstatFieldsInput(fields, ipv6), ch)
				if fields > 500 {
					require.ErrorContains(t, err, "field limit exceeded")
					require.Empty(t, ch)
				} else {
					require.NoError(t, err)
					if !ipv6 {
						require.Len(t, ch, fields)
					}
				}
			})
		}
	}
	// One shared budget across all three reads, not a cap per protocol/file.
	in := netstatFieldsInput(500, false)
	in[agentless.FileRead("/proc/net/snmp6").ID] = agentless.Result{Output: []byte("Ip6InOctets 1\n")}
	require.ErrorContains(t, (&netstatCollector{}).Update(agentless.Target{}, in, make(chan prometheus.Metric, 501)), "field limit exceeded")
	// Adding thousands of tokens beyond the limit must not allocate per token.
	small, large := netstatFieldsInput(501, false), netstatFieldsInput(2000, false)
	c := &netstatCollector{}
	ch := make(chan prometheus.Metric, 501)
	a := testing.AllocsPerRun(10, func() { _ = c.Update(agentless.Target{}, small, ch) })
	b := testing.AllocsPerRun(10, func() { _ = c.Update(agentless.Target{}, large, ch) })
	require.LessOrEqual(t, b, a+5, "hostile field count increased allocations")
}

func TestNetstatScraperFailureIsolation(t *testing.T) {
	for _, result := range []agentless.Result{{Output: []byte("Tcp: ActiveOpens\nTcp: nope\n")}, {ExitStatus: 2}} {
		in := netstatInput()
		in[agentless.FileRead("/proc/net/snmp").ID] = result
		in[agentless.FileRead("/proc/meminfo").ID] = agentless.Result{Output: []byte("MemTotal: 1 kB\n")}
		runner := &agentlesstest.FakeRunner{Results: in}
		s, err := agentless.NewScraper(runner, []agentless.Collector{&netstatCollector{}, &meminfoCollector{}}, util.TestLogger(t))
		require.NoError(t, err)
		snapshot, err := s.Scrape(t.Context(), agentless.Target{Address: "fixture"})
		require.NoError(t, err)
		require.NoError(t, testutil.CollectAndCompare(snapshot, strings.NewReader(`
# HELP node_scrape_collector_success node_exporter: Whether a collector succeeded.
# TYPE node_scrape_collector_success gauge
node_scrape_collector_success{collector="meminfo"} 1
node_scrape_collector_success{collector="netstat"} 0
# HELP node_memory_MemTotal_bytes Memory information field MemTotal_bytes.
# TYPE node_memory_MemTotal_bytes gauge
node_memory_MemTotal_bytes 1024
`), "node_scrape_collector_success", "node_memory_MemTotal_bytes"))
	}
}
