package collectors

import (
	"bytes"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	Register(Registration{Name: "edac", OS: "linux", DefaultEnabled: false, Factory: newEdacCollector})
}

const edacRoot = "/sys/devices/system/edac/mc"

var edacAttributes = [...]string{"ce_count", "ce_noinfo_count", "ue_count", "ue_noinfo_count"}

type edacCollector struct{ desc [4]*prometheus.Desc }

var _ agentless.DeepExpander = (*edacCollector)(nil)

func newEdacCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	c := &edacCollector{}
	for i, spec := range []struct {
		family, help string
		labels       []string
	}{
		{"correctable_errors_total", "Total correctable memory errors.", []string{"controller"}},
		{"csrow_correctable_errors_total", "Total correctable memory errors for this csrow.", []string{"controller", "csrow"}},
		{"uncorrectable_errors_total", "Total uncorrectable memory errors.", []string{"controller"}},
		{"csrow_uncorrectable_errors_total", "Total uncorrectable memory errors for this csrow.", []string{"controller", "csrow"}},
	} {
		c.desc[i] = prometheus.NewDesc(agentless.Namespace+"_edac_"+spec.family, spec.help, spec.labels, nil)
	}
	return c, nil
}
func (*edacCollector) Name() string { return "edac" }
func (*edacCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.CommandRead("ls", "-1", edacRoot)}
}
func edacListing(mc string) agentless.Read { return agentless.CommandRead("ls", "-1", edacRoot+"/"+mc) }
func edacRead(mc, row, attribute string) agentless.Read {
	path := edacRoot + "/" + mc
	if row != "" {
		path += "/" + row
	}
	return agentless.FileRead(path + "/" + attribute)
}

// Bound every row before converting or retaining it, including ignored sysfs
// attributes. Only exact mc<N>/csrow<N> components can influence read paths.
func edacNames(in agentless.Input, read agentless.Read, prefix string, limit int) ([]string, error) {
	if err := read.Validate(); err != nil {
		return nil, err
	}
	res := in[read.ID]
	if res.NotExist && !res.TimedOut && !res.Truncated {
		return nil, nil
	}
	output, err := in.Output(read)
	if err != nil {
		return nil, err
	}
	if len(output) == 0 {
		return nil, nil
	}
	if output[len(output)-1] != '\n' {
		return nil, fmt.Errorf("edac: unterminated listing")
	}
	var names []string
	rows := 0
	for row := range bytes.SplitSeq(output[:len(output)-1], []byte{'\n'}) {
		rows++
		if rows > agentless.MaxExpandedReads || len(row) > 4096 {
			return nil, fmt.Errorf("edac: listing limit exceeded")
		}
		if len(row) == 0 {
			return nil, fmt.Errorf("edac: empty listing row")
		}
		if !bytes.HasPrefix(row, []byte(prefix)) || len(row) == len(prefix) {
			continue
		}
		valid := true
		for _, b := range row[len(prefix):] {
			if b < '0' || b > '9' {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		if len(names) >= limit {
			return nil, fmt.Errorf("edac: expanded read limit exceeded")
		}
		name := string(row)
		for _, previous := range names {
			if previous == name {
				return nil, fmt.Errorf("edac: duplicate entry")
			}
		}
		names = append(names, name)
	}
	return names, nil
}
func (c *edacCollector) controllers(in agentless.Input) ([]string, error) {
	return edacNames(in, c.Reads()[0], "mc", min(agentless.MaxDeepListings, agentless.MaxExpandedReads/(1+len(edacAttributes))))
}
func (c *edacCollector) Expand(_ agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	controllers, err := c.controllers(in)
	if err != nil {
		return nil, err
	}
	var reads []agentless.Read
	for _, mc := range controllers {
		reads = append(reads, edacListing(mc))
		for _, attribute := range edacAttributes {
			reads = append(reads, edacRead(mc, "", attribute))
		}
	}
	for _, read := range reads {
		if err := read.Validate(); err != nil {
			return nil, err
		}
	}
	return reads, nil
}
func (c *edacCollector) ExpandDeep(_ agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	controllers, err := c.controllers(in)
	if err != nil {
		return nil, err
	}
	budget := agentless.MaxExpandedReads - len(controllers)*(1+len(edacAttributes))
	var reads []agentless.Read
	for _, mc := range controllers {
		rows, err := edacNames(in, edacListing(mc), "csrow", (budget-len(reads))/2)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			for _, attr := range []string{"ce_count", "ue_count"} {
				read := edacRead(mc, row, attr)
				if err := read.Validate(); err != nil {
					return nil, err
				}
				reads = append(reads, read)
			}
		}
	}
	return reads, nil
}
func (c *edacCollector) Update(target agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	controllers, err := c.controllers(in)
	if err != nil {
		return err
	}
	// Recheck the whole shared expansion budget before retaining any metrics.
	deep, err := c.ExpandDeep(target, in)
	if err != nil {
		return err
	}
	var metrics []prometheus.Metric
	add := func(read agentless.Read, desc *prometheus.Desc, labels ...string) error {
		if err := read.Validate(); err != nil {
			return err
		}
		res := in[read.ID]
		if res.NotExist && !res.TimedOut && !res.Truncated {
			return nil
		}
		output, err := in.Output(read)
		if err != nil {
			return err
		}
		raw := bytes.TrimSpace(output)
		if len(raw) > 20 {
			return fmt.Errorf("edac: numeric attribute too long")
		}
		value, err := strconv.ParseUint(string(raw), 10, 64)
		if err != nil {
			return fmt.Errorf("edac: invalid numeric attribute %s: %w", read.Path, err)
		}
		metrics = append(metrics, targetMetric(desc, prometheus.CounterValue, float64(value), labels...))
		return nil
	}
	for _, mc := range controllers {
		for i, attr := range edacAttributes {
			labels := []string{strings.TrimPrefix(mc, "mc")}
			if i%2 == 1 {
				labels = append(labels, "unknown")
			}
			if err := add(edacRead(mc, "", attr), c.desc[i], labels...); err != nil {
				return err
			}
		}
	}
	for _, read := range deep {
		parts := strings.Split(strings.TrimPrefix(read.Path, edacRoot+"/"), "/")
		index := 1
		if parts[2] == "ue_count" {
			index = 3
		}
		if err := add(read, c.desc[index], strings.TrimPrefix(parts[0], "mc"), strings.TrimPrefix(parts[1], "csrow")); err != nil {
			return err
		}
	}
	for _, metric := range metrics {
		ch <- metric
	}
	return nil
}
