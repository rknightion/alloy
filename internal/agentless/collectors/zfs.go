package collectors

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	Register(Registration{Name: "zfs", OS: "linux", DefaultEnabled: false, Factory: newZFSCollector})
}

type zfsCollector struct{}

func newZFSCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &zfsCollector{}, nil
}

func (*zfsCollector) Name() string { return "zfs" }

// These are node_exporter's fixed Linux kstat files. Pool listing is deliberately
// excluded: node_zfs_zpool_* (including state) and node_zfs_zpool_dataset_*.
var zfsFiles = [...]struct{ subsystem, file string }{
	{"zfs_abd", "abdstats"}, {"zfs_arc", "arcstats"},
	{"zfs_dbuf", "dbufstats"}, {"zfs_dmu_tx", "dmu_tx"},
	{"zfs_dnode", "dnodestats"}, {"zfs_fm", "fm"},
	{"zfs_vdev_cache", "vdev_cache_stats"}, {"zfs_vdev_mirror", "vdev_mirror_stats"},
	{"zfs_xuio", "xuio_stats"}, {"zfs_zfetch", "zfetchstats"}, {"zfs_zil", "zil"},
}

func (*zfsCollector) Reads() []agentless.Read {
	reads := make([]agentless.Read, 0, len(zfsFiles))
	for _, file := range zfsFiles {
		reads = append(reads, agentless.FileRead("/proc/spl/kstat/zfs/"+file.file))
	}
	return reads
}

// Count even ignored types before retention; no labels and at most 500 families.
const maxZFSRows = 500

func (c *zfsCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	var metrics []prometheus.Metric
	seen := make(map[string]bool)
	rows := 0
	for index, read := range c.Reads() {
		result := in[read.ID]
		if result.NotExist && !result.TimedOut && !result.Truncated {
			continue
		}
		output, err := in.Output(read)
		if err != nil {
			return err
		}
		scanner := bufio.NewScanner(bytes.NewReader(output))
		scanner.Buffer(make([]byte, 4096), 4096)
		header := false
		preamble := 0
		for scanner.Scan() {
			var fields [7]string
			count := 0
			for token := range strings.FieldsSeq(scanner.Text()) {
				if count == len(fields) || len(token) > 256 {
					return fmt.Errorf("zfs: excessive fields or token length")
				}
				fields[count] = token
				count++
			}
			if !header {
				if count == 3 && fields[0] == "name" && fields[1] == "type" && fields[2] == "data" {
					header = true
					continue
				}
				preamble++
				if preamble > 1 || count != 7 {
					return fmt.Errorf("zfs: malformed kstat header")
				}
				for _, field := range fields {
					if _, err := strconv.ParseUint(field, 0, 64); err != nil {
						return fmt.Errorf("zfs: malformed kstat metadata")
					}
				}
				continue
			}
			rows++
			if rows > maxZFSRows {
				return fmt.Errorf("zfs: row limit exceeded")
			}
			if count != 3 || !validZFSKey(fields[0]) {
				return fmt.Errorf("zfs: malformed kstat row")
			}
			kind, err := strconv.ParseUint(fields[1], 10, 8)
			if err != nil || kind > 7 {
				return fmt.Errorf("zfs: invalid kstat type")
			}
			if kind != 3 && kind != 4 {
				continue
			}
			value, err := strconv.ParseUint(fields[2], 10, 64)
			if err != nil {
				return fmt.Errorf("zfs: invalid kstat value")
			}
			file := zfsFiles[index]
			name := agentless.Namespace + "_" + file.subsystem + "_" + strings.ReplaceAll(fields[0], "-", "_")
			if seen[name] {
				return fmt.Errorf("zfs: duplicate family")
			}
			seen[name] = true
			metric, err := prometheus.NewConstMetric(prometheus.NewDesc(name, "kstat.zfs.misc."+file.file+"."+fields[0], nil, nil), prometheus.UntypedValue, float64(value))
			if err != nil {
				return err
			}
			metrics = append(metrics, metric)
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("zfs: scan: %w", err)
		}
		if !header {
			return fmt.Errorf("zfs: missing kstat header")
		}
	}
	for _, metric := range metrics {
		ch <- metric
	}
	return nil
}

func validZFSKey(key string) bool {
	if key == "" {
		return false
	}
	for _, c := range key {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}
