// Package agentlesstest provides test doubles for the agentless package.
package agentlesstest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

	calls    int
	root     string
	commands map[string]string
	fromFS   bool
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
		if !ok && f.fromFS {
			var err error
			res, ok, err = fixtureResult(f.root, f.commands, r)
			if err != nil {
				return nil, err
			}
		}
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
// does not exist yields exit status 1 and NotExist. Commands of the form
// ls -1 /fixed/directory list the fixture directory (excluding hidden entries),
// unless commands provides an explicit output file. Expanded reads are loaded
// on demand, so callers need only supply the fixed phase-one reads.
func FromFS(root string, commands map[string]string, reads []agentless.Read) (*FakeRunner, error) {
	f := &FakeRunner{Results: make(map[string]agentless.Result, len(reads)), root: root, commands: commands, fromFS: true}
	for _, r := range reads {
		res, ok, err := fixtureResult(root, commands, r)
		if err != nil {
			return nil, err
		}
		if ok {
			f.Results[r.ID] = res
		}
	}
	return f, nil
}

func fixtureResult(root string, commands map[string]string, r agentless.Read) (agentless.Result, bool, error) {
	if err := r.Validate(); err != nil {
		return agentless.Result{}, false, err
	}
	var name string
	switch {
	case r.Path != "":
		name = filepath.Join(root, filepath.FromSlash(r.Path))
	case commands[r.ID] != "":
		name = commands[r.ID]
	case len(r.Argv) == 3 && r.Argv[0] == "ls" && r.Argv[1] == "-1" && strings.HasPrefix(r.Argv[2], "/"):
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(r.Argv[2])))
		if os.IsNotExist(err) {
			return agentless.Result{}, false, nil
		}
		if err != nil {
			return agentless.Result{}, false, err
		}
		var output strings.Builder
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), ".") {
				output.WriteString(entry.Name())
				output.WriteByte('\n')
			}
		}
		return agentless.Result{Read: r, Output: []byte(output.String())}, true, nil
	default:
		return agentless.Result{}, false, nil
	}
	b, err := os.ReadFile(name)
	if os.IsNotExist(err) {
		return agentless.Result{}, false, nil
	}
	if err != nil {
		return agentless.Result{}, false, err
	}
	return agentless.Result{Read: r, Output: b}, true, nil
}
