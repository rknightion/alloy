package collectors

import (
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/conformance"
)

// This is a weaker, self-authored golden from real Linux output, not a
// node_exporter e2e oracle (its netdev metrics come from test-host netlink).
func TestNetdevRealOutputGolden(t *testing.T) {
	c, err := newNetdevCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Equal(t, "netdev", c.Name())
	require.Equal(t, []agentless.Read{agentless.FileRead("/proc/net/dev")}, c.Reads())
	conformance.Check(t, conformance.Case{Collector: c, Families: []string{
		"node_network_receive_bytes_total", "node_network_receive_packets_total", "node_network_receive_errs_total", "node_network_receive_drop_total", "node_network_receive_fifo_total", "node_network_receive_frame_total", "node_network_receive_compressed_total", "node_network_receive_multicast_total",
		"node_network_transmit_bytes_total", "node_network_transmit_packets_total", "node_network_transmit_errs_total", "node_network_transmit_drop_total", "node_network_transmit_fifo_total", "node_network_transmit_colls_total", "node_network_transmit_carrier_total", "node_network_transmit_compressed_total",
	}, Root: "testdata/netdev", Expected: "testdata/netdev/golden.prom"})
}

func netdevInput(output string) agentless.Input {
	r := agentless.FileRead("/proc/net/dev")
	return agentless.Input{r.ID: {Read: r, Output: []byte(output)}}
}

func TestNetdevOptions(t *testing.T) {
	require.Equal(t, NetdevConfig{}, DefaultNetdevConfig)
	data, err := os.ReadFile("testdata/netdev/proc/net/dev")
	require.NoError(t, err)
	for _, tc := range []struct {
		name    string
		cfg     NetdevConfig
		devices []string
	}{
		{"defaults", DefaultNetdevConfig, []string{"lo", "eth0"}},
		{"exclude", NetdevConfig{DeviceExclude: "^lo$"}, []string{"eth0"}},
		{"include", NetdevConfig{DeviceInclude: "^lo$"}, []string{"lo"}},
		{"include wins", NetdevConfig{DeviceInclude: "^lo$", DeviceExclude: "["}, []string{"lo"}},
		{"no match", NetdevConfig{DeviceInclude: "^missing$"}, nil},
		{"unanchored", NetdevConfig{DeviceInclude: "eth"}, []string{"eth0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newNetdevCollector(Configs{Netdev: tc.cfg}, nil)
			require.NoError(t, err)
			ch := make(chan prometheus.Metric, 64)
			require.NoError(t, c.Update(agentless.Target{}, netdevInput(string(data)), ch))
			require.Len(t, ch, len(tc.devices)*16)
			for len(ch) > 0 {
				m := &dto.Metric{}
				require.NoError(t, (<-ch).Write(m))
				require.Contains(t, tc.devices, m.Label[0].GetValue())
				require.NotNil(t, m.Counter)
			}
		})
	}
	for _, cfg := range []NetdevConfig{{DeviceInclude: "["}, {DeviceExclude: "["}} {
		_, err := newNetdevCollector(Configs{Netdev: cfg}, nil)
		require.Error(t, err)
	}
}

func TestNetdevParsing(t *testing.T) {
	headers := "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"
	c, err := newNetdevCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	ch := make(chan prometheus.Metric, 32)
	require.NoError(t, c.Update(agentless.Target{}, netdevInput(headers+" eth0:1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 18446744073709551615\n"), ch))
	for i := 1; i <= 16; i++ {
		m := &dto.Metric{}
		require.NoError(t, (<-ch).Write(m))
		want := float64(i)
		if i == 16 {
			want = float64(uint64(18446744073709551615))
		}
		require.Equal(t, want, m.Counter.GetValue())
	}
	for _, bad := range []string{"", "garbage", headers + "eth0: 1 2", headers + "eth0 1 2", headers + ": " + strings.Repeat("1 ", 16), headers + "eth0: " + strings.Repeat("1 ", 17), headers + "eth0: -1 " + strings.Repeat("1 ", 15), headers + "eth0: NaN " + strings.Repeat("1 ", 15), headers + "eth0: 18446744073709551616 " + strings.Repeat("1 ", 15), headers + "eth0: " + strings.Repeat("1 ", 16) + "\neth0: " + strings.Repeat("1 ", 16)} {
		require.Error(t, c.Update(agentless.Target{}, netdevInput(bad), ch), bad)
		require.Empty(t, ch)
	}
	require.NoError(t, c.Update(agentless.Target{}, netdevInput(headers), ch))
}

func TestNetdevReadFailuresAndConcurrentUpdates(t *testing.T) {
	c, err := newNetdevCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	r := c.Reads()[0]
	for _, result := range []agentless.Result{{ExitStatus: 1}, {Truncated: true}, {TimedOut: true}, {NotExist: true}} {
		ch := make(chan prometheus.Metric, 32)
		require.Error(t, c.Update(agentless.Target{}, agentless.Input{r.ID: result}, ch))
		require.Empty(t, ch)
	}
	require.Error(t, c.Update(agentless.Target{}, nil, make(chan prometheus.Metric, 32)))
	data, err := os.ReadFile("testdata/netdev/proc/net/dev")
	require.NoError(t, err)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Go(func() {
			ch := make(chan prometheus.Metric, 32)
			require.NoError(t, c.Update(agentless.Target{Address: "fixture"}, netdevInput(string(data)), ch))
			require.Len(t, ch, 32)
		})
	}
	wg.Wait()
}
