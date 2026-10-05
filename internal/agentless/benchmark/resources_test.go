//go:build sshscale && (darwin || linux)

package benchmark

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type resourceSample struct {
	Kind              string    `json:"kind"`
	Phase             string    `json:"phase"`
	Time              time.Time `json:"time"`
	PID               int       `json:"pid"`
	CPUSeconds        float64   `json:"process_cpu_seconds"`
	RSSBytes          int64     `json:"process_rss_bytes"`
	Goroutines        int       `json:"goroutines"`
	ServerConnections int       `json:"server_tcp_connections"`
	PoolConnections   float64   `json:"pool_ssh_connections"`
	PoolDials         float64   `json:"pool_dials_total"`
	HostKeyErrors     float64   `json:"host_key_errors_total"`
	Error             string    `json:"error,omitempty"`
}

// RUSAGE_SELF measures user+system CPU of this exact test process, not its sh
// children. ps -o rss= -p PID measures current resident memory in KiB on both
// supported hosts. The in-process SSH farm shares this PID; these measurements
// are combined client+server cost, NOT an estimate of standalone Alloy cost.
func readResources(phase string, farm []*targetServer, reg *prometheus.Registry) resourceSample {
	s := resourceSample{Kind: "resource", Phase: phase, Time: time.Now().UTC(), PID: os.Getpid(), Goroutines: runtime.NumGoroutine()}
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		s.Error = err.Error()
		return s
	}
	s.CPUSeconds = float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	data, err := exec.CommandContext(ctx, "ps", "-o", "rss=", "-p", strconv.Itoa(s.PID)).Output()
	cancel()
	if err != nil {
		s.Error = fmt.Sprintf("ps RSS: %v", err)
		return s
	}
	s.RSSBytes, err = parseRSS(data)
	if err != nil {
		s.Error = err.Error()
		return s
	}
	for _, server := range farm {
		server.mu.Lock()
		s.ServerConnections += len(server.conns)
		server.mu.Unlock()
	}
	if reg != nil {
		families, err := reg.Gather()
		if err != nil {
			s.Error = err.Error()
			return s
		}
		for _, family := range families {
			for _, metric := range family.Metric {
				switch family.GetName() {
				case "agentless_ssh_open_connections":
					s.PoolConnections = metric.GetGauge().GetValue()
				case "agentless_ssh_dials_total":
					s.PoolDials = metric.GetCounter().GetValue()
				case "agentless_ssh_host_key_failures_total":
					s.HostKeyErrors = metric.GetCounter().GetValue()
				}
			}
		}
	}
	return s
}
