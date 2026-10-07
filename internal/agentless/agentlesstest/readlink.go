package agentlesstest

import (
	"os"
	"path"
	"strings"

	"github.com/grafana/alloy/internal/agentless"
)

// Resolve symlinks in the fixture's namespace, never the host's. In particular
// absolute symlink targets start at the fixture root, not at the local /sys.
func fixtureReadlink(root string, read agentless.Read) (agentless.Result, bool, error) {
	fs, err := os.OpenRoot(root)
	if err != nil {
		return agentless.Result{}, false, err
	}
	defer fs.Close()
	failed := agentless.Result{Read: read, ExitStatus: 1}
	remaining := strings.Split(read.Argv[2], "/")
	var resolved []string
	links := 0
	for len(remaining) > 0 {
		part := remaining[0]
		remaining = remaining[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			if len(resolved) > 0 {
				resolved = resolved[:len(resolved)-1]
			}
			continue
		}
		name := path.Join(strings.Join(resolved, "/"), part)
		info, err := fs.Lstat(name)
		if os.IsNotExist(err) && len(remaining) == 0 {
			// GNU readlink -f permits a missing final component.
			resolved = append(resolved, part)
			break
		}
		if err != nil {
			return failed, true, nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			links++
			if links > 40 {
				return failed, true, nil
			}
			target, err := fs.Readlink(name)
			if err != nil || len(target) > 4096 {
				return failed, true, nil
			}
			if strings.HasPrefix(target, "/") {
				resolved = nil
			}
			remaining = append(strings.Split(target, "/"), remaining...)
			continue
		}
		if len(remaining) > 0 && !info.IsDir() {
			return failed, true, nil
		}
		resolved = append(resolved, part)
	}
	res := agentless.Result{Read: read, Output: []byte("/" + strings.Join(resolved, "/") + "\n")}
	if _, err := (agentless.Input{read.ID: res}).Output(read); err != nil {
		return failed, true, nil
	}
	return res, true, nil
}
