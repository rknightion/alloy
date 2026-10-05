// Package collectors holds the compiled-in collectors. Each collector lives in
// its own file and registers itself from init, so adding a collector touches no
// shared file beyond, when it has options, the Configs struct below.
package collectors

import (
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/grafana/alloy/internal/agentless"
)

// Factory builds a collector from the shared configuration.
type Factory func(cfg Configs, logger *slog.Logger) (agentless.Collector, error)

// Registration describes one collector.
type Registration struct {
	// Name is the node_exporter collector name.
	Name string
	// OS is the target operating system the collector's reads apply to, as
	// reported by uname -s in lower case.
	OS string
	// DefaultEnabled marks collectors enabled when the user names none.
	DefaultEnabled bool
	Factory        Factory
}

// Configs holds the options of every collector that has any. Collectors
// without options do not appear here.
type Configs struct {
	Diskstats  DiskstatsConfig
	Netdev     NetdevConfig
	Filesystem FilesystemConfig
}

// DefaultConfigs returns the default options of every collector.
func DefaultConfigs() Configs {
	return Configs{
		Diskstats:  DefaultDiskstatsConfig,
		Netdev:     DefaultNetdevConfig,
		Filesystem: DefaultFilesystemConfig,
	}
}

var (
	mu       sync.Mutex
	registry = map[string]Registration{}
)

// Register adds a collector. It panics on a duplicate or incomplete
// registration, since both are programming errors.
func Register(r Registration) {
	mu.Lock()
	defer mu.Unlock()
	if r.Name == "" || r.OS == "" || r.Factory == nil {
		panic(fmt.Sprintf("collectors: incomplete registration %+v", r))
	}
	if _, ok := registry[r.Name]; ok {
		panic("collectors: duplicate registration of " + r.Name)
	}
	registry[r.Name] = r
}

// Registered returns every registration, sorted by name.
func Registered() []Registration {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Registration, 0, len(registry))
	for _, r := range registry {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Registration) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return out
}

// DefaultEnabled returns the names of the collectors enabled by default,
// sorted.
func DefaultEnabled() []string {
	var names []string
	for _, r := range Registered() {
		if r.DefaultEnabled {
			names = append(names, r.Name)
		}
	}
	return names
}

// Validate reports an error for any name that is not a registered collector or
// appears twice.
func Validate(names []string) error {
	mu.Lock()
	defer mu.Unlock()
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if _, ok := registry[n]; !ok {
			return fmt.Errorf("unknown collector %q", n)
		}
		if seen[n] {
			return fmt.Errorf("collector %q listed twice", n)
		}
		seen[n] = true
	}
	return nil
}

// Build returns the named collectors, in the order given. An empty names
// slice builds the default-enabled collectors.
func Build(names []string, cfg Configs, logger *slog.Logger) ([]agentless.Collector, error) {
	if len(names) == 0 {
		names = DefaultEnabled()
	}
	if err := Validate(names); err != nil {
		return nil, err
	}
	out := make([]agentless.Collector, 0, len(names))
	for _, n := range names {
		mu.Lock()
		r := registry[n]
		mu.Unlock()
		c, err := r.Factory(cfg, logger)
		if err != nil {
			return nil, fmt.Errorf("collector %s: %w", n, err)
		}
		out = append(out, c)
	}
	return out, nil
}
