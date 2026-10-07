package collectors

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

// Fixtures and golden are copied byte-for-byte from node_exporter
// v0.18.1-grafana-r01.0.20251024135609-318b01780c89 sys.ttar/e2e-output.txt.
// No DMI families are omitted: upstream exports only node_dmi_info. Files
// chassis_type, modalias and uevent do not contribute labels to that family.
func TestDMIConformance(t *testing.T) {
	c, err := newDMICollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	conformance.Check(t, conformance.Case{
		Collector: c, Root: "testdata/dmi", Expected: "testdata/dmi/golden.prom",
		Families: []string{"node_dmi_info"},
	})
}

func dmiFixture(t *testing.T) (agentless.Collector, agentless.Input) {
	t.Helper()
	c, err := newDMICollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	in := agentless.Input{}
	for _, read := range c.Reads() {
		output, err := os.ReadFile("testdata/dmi" + read.Path)
		if os.IsNotExist(err) {
			in[read.ID] = agentless.Result{NotExist: true, ExitStatus: 1}
			continue
		}
		require.NoError(t, err)
		in[read.ID] = agentless.Result{Read: read, Output: output}
	}
	return c, in
}

func dmiLabels(t *testing.T, c agentless.Collector, in agentless.Input) map[string]string {
	t.Helper()
	ch := make(chan prometheus.Metric, 2)
	require.NoError(t, c.Update(agentless.Target{}, in, ch))
	close(ch)
	labels := map[string]string{}
	for metric := range ch {
		var data dto.Metric
		require.NoError(t, metric.Write(&data))
		require.Equal(t, 1.0, data.GetGauge().GetValue())
		for _, label := range data.Label {
			labels[label.GetName()] = label.GetValue()
		}
	}
	return labels
}

func TestDMIRegistrationAndReads(t *testing.T) {
	built, err := Build([]string{"dmi"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Equal(t, "dmi", built[0].Name())
	require.Contains(t, DefaultEnabled(), "dmi")
	found := false
	for _, registration := range Registered() {
		if registration.Name == "dmi" {
			found = true
			require.Equal(t, "linux", registration.OS)
			require.True(t, registration.DefaultEnabled)
		}
	}
	require.True(t, found)
	attributes := []string{"bios_date", "bios_release", "bios_vendor", "bios_version", "board_asset_tag", "board_name", "board_serial", "board_vendor", "board_version", "chassis_asset_tag", "chassis_serial", "chassis_vendor", "chassis_version", "product_family", "product_name", "product_serial", "product_sku", "product_uuid", "product_version", "sys_vendor"}
	require.Len(t, built[0].Reads(), len(attributes))
	for i, read := range built[0].Reads() {
		require.Equal(t, agentless.FileRead("/sys/class/dmi/id/"+attributes[i]), read)
		require.NoError(t, read.Validate())
	}
}

func TestDMIAttributeOmission(t *testing.T) {
	for _, status := range []int{-1, 1, 2, 126, 255} {
		for index := range 20 {
			t.Run(fmt.Sprintf("%d/%d", status, index), func(t *testing.T) {
				c, in := dmiFixture(t)
				baseline := dmiLabels(t, c, in)
				read := c.Reads()[index]
				in[read.ID] = agentless.Result{ExitStatus: status, Output: []byte("must not appear")}
				label := dmiAttributes[index]
				if label == "sys_vendor" {
					label = "system_vendor"
				}
				delete(baseline, label)
				require.Equal(t, baseline, dmiLabels(t, c, in))
			})
		}
	}
	for _, result := range []agentless.Result{{NotExist: true}, {NotExist: true, ExitStatus: 1}, {ExitStatus: 1}} {
		c, in := dmiFixture(t)
		for _, read := range c.Reads() {
			in[read.ID] = result
		}
		require.Empty(t, dmiLabels(t, c, in))
	}
}

func TestDMIValuesAndBounds(t *testing.T) {
	for _, test := range []struct{ raw, want string }{
		{"", ""}, {" \tvalue\n", "value"}, {"\"quoted", "\"quoted"},
		{"\x00\x1c[", "\x00\x1c["}, {"\xff\xfe[\xff", "�[�"},
		{strings.Repeat("x", 4096) + "\n", strings.Repeat("x", 4096)},
		{strings.Repeat("x", 4093) + "\xff", strings.Repeat("x", 4093) + "�"},
	} {
		c, in := dmiFixture(t)
		in[c.Reads()[18].ID] = agentless.Result{Output: []byte(test.raw)}
		require.Equal(t, test.want, dmiLabels(t, c, in)["product_version"])
	}
	fixture, err := os.ReadFile("testdata/dmi/sys/class/dmi/id/product_version")
	require.NoError(t, err)
	// The pinned archive already contains U+FFFD, surrounding a control byte
	// and '['. Preserve those exact bytes rather than ASCII-quoting the value.
	require.Equal(t, "efbfbd1c5befbfbd0a", fmt.Sprintf("%x", fixture))
	require.True(t, utf8.Valid(fixture))
	for _, raw := range []string{strings.Repeat("x", 4097), strings.Repeat(" ", 1000000), strings.Repeat("x", 4094) + "\xff", strings.Repeat("\xffa", 2048)} {
		c, in := dmiFixture(t)
		in[c.Reads()[19].ID] = agentless.Result{Output: []byte(raw)}
		ch := make(chan prometheus.Metric, 2)
		require.Error(t, c.Update(agentless.Target{}, in, ch))
		require.Empty(t, ch)
	}
}

func TestDMIIncompleteReads(t *testing.T) {
	for _, result := range []agentless.Result{
		{TimedOut: true}, {Truncated: true}, {NotExist: true, TimedOut: true},
		{ExitStatus: 1, Truncated: true},
	} {
		c, in := dmiFixture(t)
		in[c.Reads()[19].ID] = result
		ch := make(chan prometheus.Metric, 2)
		require.Error(t, c.Update(agentless.Target{}, in, ch))
		require.Empty(t, ch)
	}
	c, in := dmiFixture(t)
	delete(in, c.Reads()[19].ID)
	require.Error(t, c.Update(agentless.Target{}, in, make(chan prometheus.Metric, 2)))
}

func TestDMIPreRetentionAllocations(t *testing.T) {
	for _, raw := range [][]byte{[]byte(strings.Repeat("x", 1000000)), []byte(strings.Repeat("\xffa", 2048))} {
		allocs := testing.AllocsPerRun(10, func() {
			_, err := dmiValue(raw)
			if err == nil {
				panic("unbounded attribute accepted")
			}
		})
		require.LessOrEqual(t, allocs, 2.0)
	}
}
