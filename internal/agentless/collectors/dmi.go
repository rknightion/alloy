package collectors

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"unicode/utf8"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	Register(Registration{Name: "dmi", OS: "linux", DefaultEnabled: true, Factory: newDMICollector})
}

type dmiCollector struct{}

func newDMICollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &dmiCollector{}, nil
}

var dmiAttributes = [...]string{
	"bios_date", "bios_release", "bios_vendor", "bios_version",
	"board_asset_tag", "board_name", "board_serial", "board_vendor", "board_version",
	"chassis_asset_tag", "chassis_serial", "chassis_vendor", "chassis_version",
	"product_family", "product_name", "product_serial", "product_sku", "product_uuid", "product_version", "sys_vendor",
}

const dmiHelp = "A metric with a constant '1' value labeled by bios_date, bios_release, bios_vendor, bios_version, " +
	"board_asset_tag, board_name, board_serial, board_vendor, board_version, chassis_asset_tag, " +
	"chassis_serial, chassis_vendor, chassis_version, product_family, product_name, product_serial, " +
	"product_sku, product_uuid, product_version, system_vendor if provided by DMI."

func (*dmiCollector) Name() string { return "dmi" }

func (*dmiCollector) Reads() []agentless.Read {
	reads := make([]agentless.Read, len(dmiAttributes))
	for i, attribute := range dmiAttributes {
		reads[i] = agentless.FileRead("/sys/class/dmi/id/" + attribute)
	}
	return reads
}

func (c *dmiCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	var labels, values []string
	for i, read := range c.Reads() {
		result, ok := in[read.ID]
		if !ok {
			return fmt.Errorf("dmi: missing result for %s", read.Path)
		}
		if result.TimedOut || result.Truncated {
			return fmt.Errorf("dmi: incomplete attribute %s", read.Path)
		}
		// Serial numbers and UUIDs are root-only on Linux. A failed read
		// omits that label, not the other attributes or the whole collector.
		if result.NotExist || result.ExitStatus != 0 {
			continue
		}
		value, err := dmiValue(result.Output)
		if err != nil {
			return err
		}
		label := dmiAttributes[i]
		if label == "sys_vendor" {
			label = "system_vendor"
		}
		labels = append(labels, label)
		values = append(values, value)
	}
	if len(labels) == 0 {
		return nil
	}
	metric, err := prometheus.NewConstMetric(prometheus.NewDesc(agentless.Namespace+"_dmi_info", dmiHelp, labels, nil), prometheus.GaugeValue, 1, values...)
	if err != nil {
		return err
	}
	ch <- metric
	return nil
}

// One family/series and twenty fixed label names are below the frozen caps.
// Bound input before trimming, conversion or retention (allowing a sysfs final
// newline), then bound the UTF-8 replacement expansion before allocating it.
// procfs trims whitespace; the pinned exporter replaces invalid byte runs with
// U+FFFD. Do not use targetLabel's ASCII quoting here: it changes that oracle.
func dmiValue(output []byte) (string, error) {
	if len(output) > 4097 {
		return "", fmt.Errorf("dmi: attribute byte limit exceeded")
	}
	output = bytes.TrimSpace(output)
	size, invalid := 0, false
	remaining := output
	for len(remaining) > 0 {
		r, width := utf8.DecodeRune(remaining)
		if r == utf8.RuneError && width == 1 {
			if !invalid {
				size += 3
			}
			invalid = true
		} else {
			size += width
			invalid = false
		}
		if size > 4096 {
			return "", fmt.Errorf("dmi: label byte limit exceeded")
		}
		remaining = remaining[width:]
	}
	return strings.ToValidUTF8(string(output), "�"), nil
}
