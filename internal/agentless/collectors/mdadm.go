// Copyright 2015 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collectors

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"strconv"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
)

func init() {
	Register(Registration{Name: "mdadm", OS: "linux", DefaultEnabled: false, Factory: newMdadmCollector})
}

// Eleven series per device, five fixed families. Reserve space for the longest
// constant state label before retaining a device label. Component names are
// neither retained nor exported. These limits precede all target string copies.
const (
	maxMdadmDevices     = 20000 / 11
	maxMdadmDeviceBytes = 4096 - len("recovering")
	maxMdadmLineBytes   = 64 * 1024
)

var (
	mdadmStatus     = regexp.MustCompile(`^(\d+) blocks .*\[(\d+)/(\d+)\] \[([U_]+)\]$`)
	mdadmSyncBlocks = regexp.MustCompile(`\((\d+)/(\d+)\)`)
	mdadmSyncPct    = regexp.MustCompile(`=\s*([0-9.]+)%`)
	mdadmSyncFinish = regexp.MustCompile(`finish=([0-9.]+)min`)
	mdadmSyncSpeed  = regexp.MustCompile(`speed=([0-9.]+)[A-Z]`)
)

type mdadmCollector struct {
	state, disks, required, blocks, synced *prometheus.Desc
}

func newMdadmCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	desc := func(name, help string, labels ...string) *prometheus.Desc {
		return prometheus.NewDesc(agentless.Namespace+"_md_"+name, help, labels, nil)
	}
	return &mdadmCollector{
		state:    desc("state", "Indicates the state of md-device.", "device", "state"),
		disks:    desc("disks", "Number of active/failed/spare disks of device.", "device", "state"),
		required: desc("disks_required", "Total number of disks of device.", "device"),
		blocks:   desc("blocks", "Total number of blocks on device.", "device"),
		synced:   desc("blocks_synced", "Number of blocks synced on device.", "device"),
	}, nil
}

func (c *mdadmCollector) Name() string { return "mdadm" }
func (c *mdadmCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/mdstat")}
}

func (c *mdadmCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	read := c.Reads()[0]
	res := in[read.ID]
	if res.NotExist && !res.TimedOut && !res.Truncated {
		return nil
	}
	output, err := in.Output(read)
	if err != nil {
		return fmt.Errorf("mdadm: %w", err)
	}
	devices, err := parseMdadm(output)
	if err != nil {
		return err
	}
	// No series escape until the entire bounded snapshot is validated.
	for _, d := range devices {
		ch <- targetMetric(c.required, prometheus.GaugeValue, float64(d.total), d.name)
		ch <- targetMetric(c.blocks, prometheus.GaugeValue, float64(d.blocks), d.name)
		ch <- targetMetric(c.synced, prometheus.GaugeValue, float64(d.synced), d.name)
		for i, state := range [...]string{"active", "failed", "spare"} {
			ch <- targetMetric(c.disks, prometheus.GaugeValue, float64([3]int64{d.active, d.failed, d.spare}[i]), d.name, state)
		}
		for i, state := range [...]string{"active", "inactive", "recovering", "resync", "check"} {
			value := 0.0
			if d.state == i {
				value = 1
			}
			ch <- targetMetric(c.state, prometheus.GaugeValue, value, d.name, state)
		}
	}
	return nil
}

type mdadmDevice struct {
	name                                         string
	state                                        int
	active, total, failed, spare, blocks, synced int64
	striped, status, sync, bitmap                bool
}

// Streaming equivalent of procfs v0.16.1's exported MDStat fields. In contrast
// to upstream's Split/Fields/component slices, storage cannot grow with lines
// or component disks. Blank/global lines incur no per-line allocation.
func parseMdadm(output []byte) ([]mdadmDevice, error) {
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, maxMdadmLineBytes), maxMdadmLineBytes)
	var devices []mdadmDevice
	seen := make(map[string]bool)
	header := false
	var current *mdadmDevice
	fail := func() ([]mdadmDevice, error) { return nil, fmt.Errorf("mdadm: malformed mdstat") }
	for scanner.Scan() {
		raw := scanner.Bytes()
		line := bytes.TrimSpace(raw)
		if len(line) == 0 {
			continue
		}
		if bytes.HasPrefix(line, []byte("Personalities :")) {
			if header || current != nil {
				return fail()
			}
			for field := range bytes.FieldsSeq(line[len("Personalities :"):]) {
				if len(field) < 3 || field[0] != '[' || field[len(field)-1] != ']' {
					return fail()
				}
			}
			header = true
			continue
		}
		if bytes.HasPrefix(line, []byte("unused devices:")) {
			if !header || (current != nil && !current.status) {
				return fail()
			}
			current = nil
			continue
		}
		if !header {
			return fail()
		}
		if raw[0] != ' ' && raw[0] != '\t' {
			if current != nil && !current.status {
				return fail()
			}
			if len(devices) == maxMdadmDevices {
				return nil, fmt.Errorf("mdadm: device limit exceeded")
			}
			var fields [3][]byte
			n := 0
			for field := range bytes.FieldsSeq(line) {
				if n == len(fields) {
					break
				}
				fields[n] = field
				n++
			}
			if n != 3 || !bytes.Equal(fields[1], []byte(":")) || len(fields[0]) > maxMdadmDeviceBytes || !utf8.Valid(fields[0]) {
				return fail()
			}
			state := -1
			if bytes.Equal(fields[2], []byte("active")) {
				state = 0
			}
			if bytes.Equal(fields[2], []byte("inactive")) {
				state = 1
			}
			if state < 0 {
				return fail()
			}
			name := string(fields[0])
			if seen[name] {
				return fail()
			}
			seen[name] = true
			d := mdadmDevice{name: name, state: state, failed: int64(bytes.Count(line, []byte("(F)"))), spare: int64(bytes.Count(line, []byte("(S)")))}
			d.striped = bytes.Contains(line, []byte("raid0")) || bytes.Contains(line, []byte("linear"))
			if d.striped {
				d.total = int64(bytes.Count(line, []byte("[")))
				d.active = d.total
			}
			devices = append(devices, d)
			current = &devices[len(devices)-1]
			continue
		}
		if current == nil {
			return fail()
		}
		if !current.status {
			first, _, _ := bytes.Cut(line, []byte(" "))
			size, err := mdadmInt(first)
			if err != nil || !bytes.Contains(line, []byte(" blocks")) {
				return fail()
			}
			current.blocks, current.synced = size, size
			if !current.striped && current.state != 1 {
				match := mdadmStatus.FindSubmatch(line)
				if len(match) != 5 {
					return fail()
				}
				total, e1 := mdadmInt(match[2])
				active, e2 := mdadmInt(match[3])
				if e1 != nil || e2 != nil || active > total || int64(len(match[4])) != total {
					return fail()
				}
				current.total, current.active = total, active
			}
			current.status = true
			continue
		}
		if bytes.HasPrefix(line, []byte("bitmap:")) {
			if current.bitmap {
				return fail()
			}
			current.bitmap = true
			continue
		}
		if current.sync {
			return fail()
		}
		state := -1
		switch {
		case bytes.Contains(line, []byte("recovery")):
			state = 2
		case bytes.Contains(line, []byte("check")):
			state = 4
		case bytes.Contains(line, []byte("resync")):
			state = 3
		}
		if state < 0 {
			return fail()
		}
		current.state, current.sync = state, true
		if bytes.Contains(line, []byte("PENDING")) || bytes.Contains(line, []byte("DELAYED")) {
			current.synced = 0
			continue
		}
		match := mdadmSyncBlocks.FindSubmatch(line)
		if len(match) != 3 {
			return fail()
		}
		synced, e1 := mdadmInt(match[1])
		total, e2 := mdadmInt(match[2])
		if e1 != nil || e2 != nil || synced > total {
			return fail()
		}
		// Upstream also validates these fields even though the collector does not
		// export them. Do not silently accept a truncated recovery line.
		for _, re := range [...]*regexp.Regexp{mdadmSyncPct, mdadmSyncFinish, mdadmSyncSpeed} {
			m := re.FindSubmatch(line)
			if len(m) != 2 {
				return fail()
			}
			value, err := strconv.ParseFloat(string(m[1]), 64)
			if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
				return fail()
			}
		}
		current.synced = synced
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("mdadm: scan: %w", err)
	}
	if !header || (current != nil && !current.status) {
		return fail()
	}
	return devices, nil
}

func mdadmInt(raw []byte) (int64, error) {
	value, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("mdadm: invalid number")
	}
	return value, nil
}
