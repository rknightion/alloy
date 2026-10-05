// Package agentlesstest provides test doubles for the agentless package.
package agentlesstest

import (
	"context"
	"os"
	"path/filepath"
	"sync"

	"github.com/grafana/alloy/internal/agentless"
)

// FakeRunner is an agentless.Runner that answers reads from memory.
type FakeRunner struct {
	mu sync.Mutex

	// Results maps a Read.ID to the result returned for it. A read with no
	// entry gets exit status 1 and NotExist, like a missing file.
	Results map[string]agentless.Result
	// Err, when set, is returned by Run instead of any results.
	Err error

	calls int
}

var _ agentless.Runner = (*FakeRunner)(nil)

// Run implements agentless.Runner.
func (f *FakeRunner) Run(ctx context.Context, _ agentless.Target, reads []agentless.Read) ([]agentless.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.Err != nil {
		return nil, f.Err
	}
	out := make([]agentless.Result, len(reads))
	for i, r := range reads {
		res, ok := f.Results[r.ID]
		if !ok {
			res = agentless.Result{ExitStatus: 1, NotExist: true}
		}
		res.Read = r
		out[i] = res
	}
	return out, nil
}

// Calls returns how many times Run was called.
func (f *FakeRunner) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// FromFS returns a FakeRunner whose file reads are answered from the
// directory root, which mirrors the target's filesystem: the read of /proc/stat
// is answered from root/proc/stat. Command reads are answered from commands,
// which maps a Read.ID to a file holding that command's output. A file that
// does not exist yields exit status 1 and NotExist.
func FromFS(root string, commands map[string]string, reads []agentless.Read) (*FakeRunner, error) {
	f := &FakeRunner{Results: make(map[string]agentless.Result, len(reads))}
	for _, r := range reads {
		var name string
		if r.Path != "" {
			name = filepath.Join(root, filepath.FromSlash(r.Path))
		} else if p, ok := commands[r.ID]; ok {
			name = p
		} else {
			continue
		}
		b, err := os.ReadFile(name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		f.Results[r.ID] = agentless.Result{Read: r, Output: b}
	}
	return f, nil
}
