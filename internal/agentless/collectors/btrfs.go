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

// Sysfs only: node_btrfs_device_errors_total (write, read, flush,
// corruption, generation), node_btrfs_device_unused_bytes and the
// btrfs_dev_uuid label require ioctls and are deliberately omitted.
func init() {
	Register(Registration{Name: "btrfs", OS: "linux", DefaultEnabled: false, Factory: newBtrfsCollector})
}

const btrfsRoot = "/sys/fs/btrfs"

var btrfsGroups = [...]string{"data", "metadata", "system"}
var btrfsModes = [...]string{"single", "dup", "raid0", "raid1", "raid10", "raid1c3", "raid1c4", "raid5", "raid6"}

type btrfsCollector struct{ desc [7]*prometheus.Desc }

var _ agentless.DeepExpander = (*btrfsCollector)(nil)

func newBtrfsCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	c := &btrfsCollector{}
	for i, s := range []struct {
		name, help string
		labels     []string
	}{
		{"info", "Filesystem information", []string{"uuid", "label"}},
		{"global_rsv_size_bytes", "Size of global reserve.", []string{"uuid"}},
		{"reserved_bytes", "Amount of space reserved for a data type", []string{"uuid", "block_group_type"}},
		{"used_bytes", "Amount of used space by a layout/data type", []string{"uuid", "block_group_type", "mode"}},
		{"size_bytes", "Amount of space allocated for a layout/data type", []string{"uuid", "block_group_type", "mode"}},
		{"allocation_ratio", "Data allocation ratio for a layout/data type", []string{"uuid", "block_group_type", "mode"}},
		{"device_size_bytes", "Size of a device that is part of the filesystem.", []string{"uuid", "device"}},
	} {
		c.desc[i] = prometheus.NewDesc(agentless.Namespace+"_btrfs_"+s.name, s.help, s.labels, nil)
	}
	return c, nil
}
func (*btrfsCollector) Name() string { return "btrfs" }
func (*btrfsCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.CommandRead("ls", "-1", btrfsRoot)}
}
func btrfsFile(fs, attr string) agentless.Read {
	return agentless.FileRead(btrfsRoot + "/" + fs + "/" + attr)
}
func btrfsList(fs, dir string) agentless.Read {
	return agentless.CommandRead("ls", "-1", btrfsRoot+"/"+fs+"/"+dir)
}
func btrfsOutput(in agentless.Input, read agentless.Read) ([]byte, bool, error) {
	if err := read.Validate(); err != nil {
		return nil, false, err
	}
	res := in[read.ID]
	if res.NotExist && !res.TimedOut && !res.Truncated {
		return nil, false, nil
	}
	out, err := in.Output(read)
	return out, err == nil, err
}

// Bound even ignored rows before converting them to strings or retaining them.
func btrfsNames(in agentless.Input, read agentless.Read, accept func([]byte) bool, limit int) ([]string, error) {
	out, _, err := btrfsOutput(in, read)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	if out[len(out)-1] != '\n' {
		return nil, fmt.Errorf("btrfs: unterminated listing")
	}
	var names []string
	rows := 0
	for row := range bytes.SplitSeq(out[:len(out)-1], []byte{'\n'}) {
		rows++
		if rows > agentless.MaxExpandedReads || len(row) > 4096 || len(row) == 0 {
			return nil, fmt.Errorf("btrfs: listing limit exceeded")
		}
		if !accept(row) {
			continue
		}
		if len(names) >= limit {
			return nil, fmt.Errorf("btrfs: expansion limit exceeded")
		}
		name := string(row)
		for _, prior := range names {
			if prior == name {
				return nil, fmt.Errorf("btrfs: duplicate listing entry")
			}
		}
		names = append(names, name)
	}
	return names, nil
}
func btrfsUUID(row []byte) bool {
	if len(row) != 36 {
		return false
	}
	for i, b := range row {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if b != '-' {
				return false
			}
			continue
		}
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F') {
			return false
		}
	}
	return true
}
func btrfsDevice(row []byte) bool {
	if len(row) > 255 || bytes.Contains(row, []byte("..")) {
		return false
	}
	for _, b := range row {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-' || b == '.') {
			return false
		}
	}
	return string(row) != "."
}
func btrfsMode(row []byte) bool {
	for _, mode := range btrfsModes {
		if bytes.Equal(row, []byte(mode)) {
			return true
		}
	}
	return false
}
func (c *btrfsCollector) filesystems(in agentless.Input) ([]string, error) {
	return btrfsNames(in, c.Reads()[0], btrfsUUID, agentless.MaxDeepListings/4)
}
func (c *btrfsCollector) Expand(_ agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	names, err := c.filesystems(in)
	if err != nil {
		return nil, err
	}
	var reads []agentless.Read
	for _, fs := range names {
		reads = append(reads, btrfsList(fs, "devices"), btrfsFile(fs, "label"), btrfsFile(fs, "metadata_uuid"), btrfsFile(fs, "allocation/global_rsv_size"))
		for _, group := range btrfsGroups {
			reads = append(reads, btrfsList(fs, "allocation/"+group), btrfsFile(fs, "allocation/"+group+"/bytes_reserved"))
		}
	}
	for _, read := range reads {
		if err := read.Validate(); err != nil {
			return nil, err
		}
	}
	return reads, nil
}
func (c *btrfsCollector) ExpandDeep(target agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	names, err := c.filesystems(in)
	if err != nil {
		return nil, err
	}
	second, err := c.Expand(target, in)
	if err != nil {
		return nil, err
	}
	budget := agentless.MaxExpandedReads - len(second)
	var reads []agentless.Read
	for _, fs := range names {
		devices, err := btrfsNames(in, btrfsList(fs, "devices"), btrfsDevice, budget-len(reads))
		if err != nil {
			return nil, err
		}
		for _, dev := range devices {
			reads = append(reads, btrfsFile(fs, "devices/"+dev+"/size"))
		}
		for _, group := range btrfsGroups {
			modes, err := btrfsNames(in, btrfsList(fs, "allocation/"+group), btrfsMode, (budget-len(reads))/2)
			if err != nil {
				return nil, err
			}
			for _, mode := range modes {
				for _, attr := range []string{"used_bytes", "total_bytes"} {
					reads = append(reads, btrfsFile(fs, "allocation/"+group+"/"+mode+"/"+attr))
				}
			}
		}
	}
	for _, read := range reads {
		if err := read.Validate(); err != nil {
			return nil, err
		}
	}
	return reads, nil
}
func (c *btrfsCollector) Update(target agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	names, err := c.filesystems(in)
	if err != nil {
		return err
	}
	if _, err = c.ExpandDeep(target, in); err != nil {
		return err
	}
	var metrics []prometheus.Metric
	add := func(index int, value float64, labels ...string) {
		metrics = append(metrics, targetMetric(c.desc[index], prometheus.GaugeValue, value, labels...))
	}
	number := func(fs, attr string, index int, multiplier float64, labels ...string) error {
		out, present, err := btrfsOutput(in, btrfsFile(fs, attr))
		if err != nil {
			return err
		}
		if !present {
			return nil
		}
		raw := bytes.TrimSpace(out)
		if len(raw) > 20 {
			return fmt.Errorf("btrfs: numeric attribute too long")
		}
		value, err := strconv.ParseUint(string(raw), 10, 64)
		if err != nil {
			return fmt.Errorf("btrfs: invalid attribute %s: %w", attr, err)
		}
		add(index, float64(value)*multiplier, labels...)
		return nil
	}
	text := func(fs, attr string, max int) (string, bool, error) {
		out, present, err := btrfsOutput(in, btrfsFile(fs, attr))
		if err != nil {
			return "", false, err
		}
		if len(out) > max {
			return "", false, fmt.Errorf("btrfs: text attribute too long")
		}
		return string(bytes.TrimSpace(out)), present, nil
	}
	for _, fs := range names {
		uuid, _, err := text(fs, "metadata_uuid", 64)
		if err != nil {
			return err
		}
		if uuid == "" {
			uuid = fs
		} else if !btrfsUUID([]byte(uuid)) {
			return fmt.Errorf("btrfs: invalid metadata UUID")
		}
		label, present, err := text(fs, "label", 257)
		if err != nil {
			return err
		}
		if present {
			add(0, 1, uuid, label)
		}
		if err := number(fs, "allocation/global_rsv_size", 1, 1, uuid); err != nil {
			return err
		}
		devices, err := btrfsNames(in, btrfsList(fs, "devices"), btrfsDevice, agentless.MaxExpandedReads)
		if err != nil {
			return err
		}
		for _, dev := range devices {
			if err := number(fs, "devices/"+dev+"/size", 6, 512, uuid, dev); err != nil {
				return err
			}
		}
		for _, group := range btrfsGroups {
			if err := number(fs, "allocation/"+group+"/bytes_reserved", 2, 1, uuid, group); err != nil {
				return err
			}
			modes, err := btrfsNames(in, btrfsList(fs, "allocation/"+group), btrfsMode, agentless.MaxExpandedReads)
			if err != nil {
				return err
			}
			for _, mode := range modes {
				for i, attr := range []string{"used_bytes", "total_bytes"} {
					if err := number(fs, "allocation/"+group+"/"+mode+"/"+attr, 3+i, 1, uuid, group, mode); err != nil {
						return err
					}
				}
				ratio := 1.0
				switch mode {
				case "dup", "raid1", "raid10":
					ratio = 2
				case "raid1c3":
					ratio = 3
				case "raid1c4":
					ratio = 4
				case "raid5", "raid6":
					parity := 1
					if strings.HasSuffix(mode, "6") {
						parity = 2
					}
					if len(devices) == 0 {
						// A missing device directory has no ratio to export.
						continue
					}
					if len(devices) <= parity {
						return fmt.Errorf("btrfs: insufficient devices for parity layout")
					}
					ratio = float64(len(devices)) / float64(len(devices)-parity)
				}
				add(5, ratio, uuid, group, mode)
			}
		}
	}
	for _, metric := range metrics {
		ch <- metric
	}
	return nil
}
