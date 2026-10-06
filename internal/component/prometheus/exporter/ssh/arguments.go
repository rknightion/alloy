// Package ssh exposes node_exporter-compatible host metrics over SSH.
package ssh

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/collectors"
	"github.com/grafana/alloy/internal/agentless/sshrunner"
	"github.com/grafana/alloy/internal/component/discovery"
	"github.com/grafana/alloy/syntax/alloytypes"
)

// Auth contains credentials supplied by Alloy secret-producing components.
type Auth struct {
	Name       string            `alloy:",label"`
	Username   string            `alloy:"username,attr"`
	PrivateKey alloytypes.Secret `alloy:"private_key,attr,optional"`
	Passphrase alloytypes.Secret `alloy:"passphrase,attr,optional"`
	Password   alloytypes.Secret `alloy:"password,attr,optional"`
}

// Target configures one permitted SSH destination.
type Target struct {
	Name    string            `alloy:",label"`
	Address string            `alloy:"address,attr"`
	Auth    string            `alloy:"auth,attr,optional"`
	Labels  map[string]string `alloy:"labels,attr,optional"`

	collectorNames   []string
	invalidSelection bool
}

type DiskstatsConfig struct {
	DeviceInclude string `alloy:"device_include,attr,optional"`
	DeviceExclude string `alloy:"device_exclude,attr,optional"`
}

func (c *DiskstatsConfig) SetToDefault() {
	c.DeviceExclude = collectors.DefaultDiskstatsConfig.DeviceExclude
}

type NetdevConfig struct {
	DeviceInclude string `alloy:"device_include,attr,optional"`
	DeviceExclude string `alloy:"device_exclude,attr,optional"`
}

func (c *NetdevConfig) SetToDefault() { c.DeviceExclude = collectors.DefaultNetdevConfig.DeviceExclude }

type FilesystemConfig struct {
	MountPointsExclude string `alloy:"mount_points_exclude,attr,optional"`
	FSTypesExclude     string `alloy:"fs_types_exclude,attr,optional"`
}

func (c *FilesystemConfig) SetToDefault() {
	c.MountPointsExclude = collectors.DefaultFilesystemConfig.MountPointsExclude
	c.FSTypesExclude = collectors.DefaultFilesystemConfig.FSTypesExclude
}

// Arguments controls the transport, permitted targets and compiled-in collectors.
type Arguments struct {
	Auths                []Auth                    `alloy:"auth,block"`
	KnownHosts           alloytypes.OptionalSecret `alloy:"known_hosts,attr,optional"`
	KnownHostsFiles      []string                  `alloy:"known_hosts_files,attr,optional"`
	Targets              []Target                  `alloy:"target,block,optional"`
	TargetsList          []discovery.Target        `alloy:"targets,attr,optional"`
	EnabledCollectors    []string                  `alloy:"enabled_collectors,attr,optional"`
	Diskstats            DiskstatsConfig           `alloy:"diskstats,block,optional"`
	Netdev               NetdevConfig              `alloy:"netdev,block,optional"`
	Filesystem           FilesystemConfig          `alloy:"filesystem,block,optional"`
	Timeout              time.Duration             `alloy:"timeout,attr,optional"`
	DialTimeout          time.Duration             `alloy:"dial_timeout,attr,optional"`
	MaxSessionsPerTarget int                       `alloy:"max_sessions_per_target,attr,optional"`
	MaxConcurrentDials   int                       `alloy:"max_concurrent_dials,attr,optional"`
	IdleTimeout          time.Duration             `alloy:"idle_timeout,attr,optional"`
	KeepaliveInterval    time.Duration             `alloy:"keepalive_interval,attr,optional"`
	KeepaliveTimeout     time.Duration             `alloy:"keepalive_timeout,attr,optional"`
}

func (a *Arguments) SetToDefault() {
	*a = Arguments{
		Timeout: sshrunner.DefaultConfig.Timeout, DialTimeout: sshrunner.DefaultConfig.DialTimeout,
		MaxSessionsPerTarget: sshrunner.DefaultConfig.MaxSessionsPerTarget, MaxConcurrentDials: sshrunner.DefaultConfig.MaxConcurrentDials,
		IdleTimeout: sshrunner.DefaultConfig.IdleTimeout, KeepaliveInterval: sshrunner.DefaultConfig.KeepaliveInterval, KeepaliveTimeout: sshrunner.DefaultConfig.KeepaliveTimeout,
	}
	a.Diskstats.SetToDefault()
	a.Netdev.SetToDefault()
	a.Filesystem.SetToDefault()
}

func (a Arguments) collectorConfigs() collectors.Configs {
	return collectors.Configs{
		Diskstats:  collectors.DiskstatsConfig{DeviceInclude: a.Diskstats.DeviceInclude, DeviceExclude: a.Diskstats.DeviceExclude},
		Netdev:     collectors.NetdevConfig{DeviceInclude: a.Netdev.DeviceInclude, DeviceExclude: a.Netdev.DeviceExclude},
		Filesystem: collectors.FilesystemConfig{MountPointsExclude: a.Filesystem.MountPointsExclude, FSTypesExclude: a.Filesystem.FSTypesExclude},
	}
}

func (a Arguments) poolConfig() sshrunner.Config {
	cfg := sshrunner.DefaultConfig
	cfg.Auths = make(map[string]sshrunner.Auth, len(a.Auths))
	for _, auth := range a.Auths {
		cfg.Auths[auth.Name] = sshrunner.Auth{Username: auth.Username, PrivateKey: []byte(auth.PrivateKey), Passphrase: []byte(auth.Passphrase), Password: []byte(auth.Password)}
	}
	cfg.KnownHosts = a.KnownHosts.Value
	cfg.KnownHostsFiles = a.KnownHostsFiles
	targets := a.targets()
	cfg.Targets = make([]agentless.Target, 0, len(targets))
	for _, target := range targets {
		if target.invalidSelection {
			continue
		}
		cfg.Targets = append(cfg.Targets, agentless.Target{Address: target.Address, Auth: target.Auth})
	}
	cfg.Timeout, cfg.DialTimeout = a.Timeout, a.DialTimeout
	cfg.MaxSessionsPerTarget, cfg.MaxConcurrentDials = a.MaxSessionsPerTarget, a.MaxConcurrentDials
	cfg.IdleTimeout, cfg.KeepaliveInterval, cfg.KeepaliveTimeout = a.IdleTimeout, a.KeepaliveInterval, a.KeepaliveTimeout
	return cfg
}

func (a Arguments) targets() []Target {
	global := slices.Clone(a.EnabledCollectors)
	if len(global) == 0 {
		global = collectors.DefaultEnabled()
	}
	if len(a.Targets) > 0 {
		out := slices.Clone(a.Targets)
		for i := range out {
			if out[i].Auth == "" {
				out[i].Auth = sshrunner.DefaultAuthName
			}
			out[i].collectorNames = slices.Clone(global)
		}
		return out
	}
	out := make([]Target, 0, len(a.TargetsList))
	for _, dt := range a.TargetsList {
		address, _ := dt.Get("address")
		if address == "" {
			address, _ = dt.Get("__address__")
		}
		labels := make(map[string]string)
		dt.ForEachLabel(func(k, v string) bool {
			if k != "address" && k != "__address__" && k != "name" && k != "auth" {
				labels[k] = v
			}
			return true
		})
		name, _ := dt.Get("name")
		auth, _ := dt.Get("__param_auth")
		if auth == "" {
			auth = sshrunner.DefaultAuthName
		}
		names := slices.Clone(global)
		selector, _ := dt.Get("__param_collectors")
		if selector != "" {
			names = strings.Split(selector, ",")
		}
		invalid := !slices.ContainsFunc(a.Auths, func(a Auth) bool { return a.Name == auth }) || collectors.Validate(names) != nil
		for _, n := range names {
			if !slices.Contains(global, n) {
				invalid = true
			}
		}
		out = append(out, Target{Name: name, Address: address, Auth: auth, Labels: labels, collectorNames: names, invalidSelection: invalid})
	}
	return out
}

// Validate rejects unknown collectors, ambiguous targets and unsafe options.
func (a Arguments) Validate() error {
	if a.KnownHosts.Value == "" && len(a.KnownHostsFiles) == 0 {
		return errors.New("known_hosts or known_hosts_files is required")
	}
	if len(a.Auths) == 0 {
		return errors.New("at least one auth block is required")
	}
	auths := make(map[string]bool)
	for _, auth := range a.Auths {
		if auth.Name == "" || auth.Username == "" || (auth.PrivateKey == "" && auth.Password == "") {
			return errors.New("each auth requires a name, username and credentials")
		}
		if auths[auth.Name] {
			return errors.New("duplicate auth name")
		}
		auths[auth.Name] = true
		if auth.Passphrase != "" && auth.PrivateKey == "" {
			return errors.New("passphrase requires private_key")
		}
	}
	if len(a.Targets) > 0 && len(a.TargetsList) > 0 {
		return errors.New("target blocks and targets attribute are mutually exclusive")
	}
	seen := make(map[string]bool)
	for _, t := range a.targets() {
		if err := validateAddress(t.Address); err != nil {
			return err
		}
		address := targetKey(t.Address)
		if seen[address] {
			return errors.New("duplicate target address")
		}
		seen[address] = true
		auth := t.Auth
		if auth == "" {
			auth = sshrunner.DefaultAuthName
		}
		if len(a.Targets) > 0 && !auths[auth] {
			return errors.New("target selects an undefined auth")
		}
	}
	if a.Timeout <= 0 || a.DialTimeout <= 0 || a.IdleTimeout <= 0 || a.KeepaliveInterval <= 0 || a.KeepaliveTimeout <= 0 {
		return errors.New("timeouts must be positive")
	}
	if a.MaxSessionsPerTarget < 1 || a.MaxSessionsPerTarget >= 10 || a.MaxConcurrentDials < 1 {
		return errors.New("invalid session or dial limits")
	}
	if err := collectors.Validate(a.EnabledCollectors); err != nil {
		return err
	}
	patterns := []string{a.Filesystem.MountPointsExclude, a.Filesystem.FSTypesExclude}
	for _, pair := range [][2]string{{a.Diskstats.DeviceInclude, a.Diskstats.DeviceExclude}, {a.Netdev.DeviceInclude, a.Netdev.DeviceExclude}} {
		pattern := pair[0]
		if pattern == "" {
			pattern = pair[1]
		}
		patterns = append(patterns, pattern)
	}
	for _, p := range patterns {
		if _, err := regexp.Compile(p); err != nil {
			return errors.New("invalid collector regular expression")
		}
	}
	// Only the reserved __param_auth label selects discovery credentials.
	for _, t := range a.TargetsList {
		if auth, _ := t.Get("auth"); auth != "" {
			return errors.New("auth selection from discovery labels is not supported")
		}
	}
	return nil
}

// targetKey compares validated destinations without changing the configured
// address used by the HTTP allowlist or the exported instance label.
func targetKey(address string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host, port = address, sshrunner.DefaultPort
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	n, _ := strconv.Atoi(port)
	return net.JoinHostPort(strings.ToLower(host), strconv.Itoa(n))
}

func validateAddress(address string) error {
	if address == "" || strings.ContainsAny(address, "/\\@?# \t\r\n") {
		return errors.New("target requires a host or host:port address")
	}
	host := address
	if strings.Contains(address, ":") && net.ParseIP(address) == nil {
		var port string
		var err error
		host, port, err = net.SplitHostPort(address)
		if err != nil {
			return errors.New("invalid target host:port")
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("invalid target port")
		}
	}
	if host == "" {
		return fmt.Errorf("target host is empty")
	}
	return nil
}
