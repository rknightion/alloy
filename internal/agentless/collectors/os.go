package collectors

import (
	"bytes"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"

	envparse "github.com/hashicorp/go-envparse"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
)

func init() {
	Register(Registration{Name: "os", OS: "linux", DefaultEnabled: true, Factory: newOSCollector})
}

type osCollector struct{}

func newOSCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &osCollector{}, nil
}

// Name implements agentless.Collector.
func (c *osCollector) Name() string { return "os" }

// Reads implements agentless.Collector.
func (c *osCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/etc/os-release"), agentless.FileRead("/usr/lib/os-release")}
}

// Update implements agentless.Collector.
func (c *osCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	var output []byte
	found := false
	for _, read := range c.Reads() {
		result, ok := in[read.ID]
		if ok && result.NotExist {
			continue
		}
		var err error
		output, err = in.Output(read)
		if err != nil {
			return err
		}
		// /etc overrides /usr/lib completely; only a missing file permits
		// fallback, not permission errors or malformed content.
		found = true
		break
	}
	if !found {
		return fmt.Errorf("os: no os-release file found")
	}
	// Parse data only, never source it as shell code. Use the same quoting
	// parser as the pinned node_exporter, including literal single quotes.
	env, err := envparse.Parse(bytes.NewReader(output))
	if err != nil {
		return fmt.Errorf("os: parse os-release: %w", err)
	}
	var version float64
	if prefix := osVersionPrefix.FindString(env["VERSION_ID"]); prefix != "" {
		version, err = strconv.ParseFloat(prefix, 64)
		if err != nil {
			return fmt.Errorf("os: parse version: %w", err)
		}
	}
	ch <- prometheus.MustNewConstMetric(osInfoDesc, prometheus.GaugeValue, 1,
		env["BUILD_ID"], env["ID"], env["ID_LIKE"], env["IMAGE_ID"], env["IMAGE_VERSION"],
		env["NAME"], env["PRETTY_NAME"], env["VARIANT"], env["VARIANT_ID"], env["VERSION"],
		env["VERSION_CODENAME"], env["VERSION_ID"])
	if version > 0 {
		ch <- prometheus.MustNewConstMetric(osVersionDesc, prometheus.GaugeValue, version,
			env["ID"], env["ID_LIKE"], env["NAME"])
	}
	return nil
}

var (
	osVersionPrefix = regexp.MustCompile(`^[0-9]+\.?[0-9]*`)
	osInfoDesc      = prometheus.NewDesc(
		prometheus.BuildFQName(agentless.Namespace, "os", "info"),
		"A metric with a constant '1' value labeled by build_id, id, id_like, image_id, image_version, name, pretty_name, variant, variant_id, version, version_codename, version_id.",
		[]string{"build_id", "id", "id_like", "image_id", "image_version", "name", "pretty_name", "variant", "variant_id", "version", "version_codename", "version_id"}, nil,
	)
	osVersionDesc = prometheus.NewDesc(
		prometheus.BuildFQName(agentless.Namespace, "os", "version"),
		"Metric containing the major.minor part of the OS version.",
		[]string{"id", "id_like", "name"}, nil,
	)
)
