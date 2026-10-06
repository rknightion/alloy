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
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
)

func init() {
	Register(Registration{Name: "udp_queues", OS: "linux", DefaultEnabled: true, Factory: newUDPQueuesCollector})
}

type udpQueuesCollector struct{ desc *prometheus.Desc }

func newUDPQueuesCollector(_ Configs, _ *slog.Logger) (agentless.Collector, error) {
	return &udpQueuesCollector{desc: prometheus.NewDesc(agentless.Namespace+"_udp_queues",
		"Number of allocated memory in the kernel for UDP datagrams in bytes.", []string{"queue", "ip"}, nil)}, nil
}

func (c *udpQueuesCollector) Name() string { return "udp_queues" }

func (c *udpQueuesCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/net/udp"), agentless.FileRead("/proc/net/udp6")}
}

func (c *udpQueuesCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	// Validate both inputs before emitting anything, including when udp6 fails
	// after a valid IPv4 snapshot. Missing files suppress only their IP's series.
	var totals [2][2]uint64
	var present [2]bool
	for i, read := range c.Reads() {
		result, ok := in[read.ID]
		if ok && result.NotExist && !result.Truncated && !result.TimedOut {
			continue
		}
		output, err := in.Output(read)
		if err != nil {
			return fmt.Errorf("udp_queues: %w", err)
		}
		totals[i], err = parseUDPQueues(output)
		if err != nil {
			return err
		}
		present[i] = true
	}
	for i, ip := range []string{"v4", "v6"} {
		if present[i] {
			ch <- targetMetric(c.desc, prometheus.GaugeValue, float64(totals[i][0]), "tx", ip)
			ch <- targetMetric(c.desc, prometheus.GaugeValue, float64(totals[i][1]), "rx", ip)
		}
	}
	return nil
}

// Parsing retains only two sums, not sockets: exactly one family, at most four
// series, and fixed labels far below the 4096-byte label cap. Bound each line
// before tokenizing, and use a fixed field array rather than allocating a slice
// proportional to hostile input. Continue through all rows to detect bad tails.
const maxUDPQueuesLineBytes = 4096

func parseUDPQueues(output []byte) ([2]uint64, error) {
	var totals [2]uint64
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, maxUDPQueuesLineBytes), maxUDPQueuesLineBytes)
	if !scanner.Scan() {
		return totals, fmt.Errorf("udp_queues: missing header")
	}
	header := strings.Join(strings.Fields(scanner.Text()), " ")
	header = strings.Replace(header, " remote_address ", " rem_address ", 1)
	const baseHeader = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode"
	if header != baseHeader && header != baseHeader+" ref pointer drops" {
		return totals, fmt.Errorf("udp_queues: malformed header")
	}
	for scanner.Scan() {
		var fields [17]string
		n := 0
		for field := range bytes.FieldsSeq(scanner.Bytes()) {
			if n == len(fields) {
				return totals, fmt.Errorf("udp_queues: too many socket fields")
			}
			fields[n] = string(field)
			n++
		}
		if n < 13 {
			return totals, fmt.Errorf("udp_queues: incomplete socket row")
		}
		// Validate the same fields as procfs.parseNetIPSocketLine, without retaining
		// address objects or per-socket structs. Extra kernel fields are not exported.
		slot, suffix, ok := strings.Cut(fields[0], ":")
		if !ok || suffix != "" || !udpQueuesUint(slot, 0) {
			return totals, fmt.Errorf("udp_queues: invalid socket slot")
		}
		for _, field := range fields[1:3] {
			address, port, ok := strings.Cut(field, ":")
			if !ok || (len(address) != 8 && len(address) != 32) || !udpQueuesHex(address) || !udpQueuesUint(port, 16) {
				return totals, fmt.Errorf("udp_queues: invalid socket address")
			}
		}
		if !udpQueuesUint(fields[3], 16) || !udpQueuesUint(fields[7], 0) || !udpQueuesUint(fields[9], 0) || !udpQueuesUint(fields[12], 0) {
			return totals, fmt.Errorf("udp_queues: invalid socket numeric field")
		}
		tx, rx, ok := strings.Cut(fields[4], ":")
		if !ok {
			return totals, fmt.Errorf("udp_queues: invalid queue pair")
		}
		a, errA := strconv.ParseUint(tx, 16, 64)
		b, errB := strconv.ParseUint(rx, 16, 64)
		if errA != nil || errB != nil {
			return totals, fmt.Errorf("udp_queues: invalid queue value")
		}
		// uint64 addition matches upstream summary semantics.
		totals[0] += a
		totals[1] += b
	}
	if err := scanner.Err(); err != nil {
		return totals, fmt.Errorf("udp_queues: scan sockets: %w", err)
	}
	return totals, nil
}

func udpQueuesUint(field string, base int) bool {
	_, err := strconv.ParseUint(field, base, 64)
	return err == nil
}

func udpQueuesHex(field string) bool {
	for _, c := range field {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
