package ssh_test

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestDefaultDispatch compiles the actual harness selection boundary with fake
// legacy runners and a fake Go process. It cannot start the shared Compose stack
// or contact Docker, but observes which runner default enumeration selects.
func TestDefaultDispatch(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "../../utils.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var functions bytes.Buffer
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && (fn.Name.Name == "runTest" || fn.Name.Name == "runSSHTest" || fn.Name.Name == "isSSHTestDir") {
			if err := printer.Fprint(&functions, fset, fn); err != nil {
				t.Fatal(err)
			}
			functions.WriteByte('\n')
		}
	}
	mainFile, err := parser.ParseFile(fset, "../../main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var earlyCondition bytes.Buffer
	for _, decl := range mainFile.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Name.Name == "resolveTestDir" {
			if err := printer.Fprint(&functions, fset, fn); err != nil {
				t.Fatal(err)
			}
			functions.WriteByte('\n')
		}
		if fn.Name.Name == "runIntegrationTests" {
			for _, stmt := range fn.Body.List {
				if branch, ok := stmt.(*ast.IfStmt); ok {
					if err := printer.Fprint(&earlyCondition, fset, branch.Cond); err != nil {
						t.Fatal(err)
					}
					break
				}
			}
		}
	}
	if earlyCondition.Len() == 0 {
		t.Fatal("missing early dispatch condition")
	}
	functions.WriteString("func earlyDispatch(specificTest string) bool { return " + earlyCondition.String() + " }\n")
	dir := t.TempDir()
	source := `package main
import (
 "context"
 "fmt"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
 "time"
)
// Keep imports valid while testing the pre-repair dispatcher too.
var _ = fmt.Sprintf
var _ = exec.CommandContext
var _ = filepath.Base
var repoRootDir, testsRootDir string
var selected string
var logs []TestLog
type TestLog struct { TestDir string; IsError bool; AlloyLog, TestOutput string }
func addLog(l TestLog) { logs = append(logs, l) }
func hasComposeFile(dir string) bool { return strings.HasSuffix(dir, "compose-case") }
func runComposeTest(context.Context, string, bool, time.Duration) { selected = "compose" }
func runTestWithTestcontainers(context.Context, string, int, bool, time.Duration) { selected = "legacy" }
` + functions.String() + `
func TestSelection(t *testing.T) {
 repoRootDir = t.TempDir()
 testsRootDir = filepath.Join(repoRootDir, "integration-tests/docker")
 for _, filter := range []string{"ssh-exporter", "./tests/ssh-exporter", filepath.Join(testsRootDir, "tests/ssh-exporter")} {
  if !earlyDispatch(filter) { t.Fatalf("SSH filter %q enters shared setup", filter) }
 }
 if earlyDispatch("") || earlyDispatch("ordinary-case") || earlyDispatch(filepath.Join(t.TempDir(), "ssh-exporter")) {
  t.Fatal("non-SSH filter changed early route")
 }
 fakeBin := t.TempDir()
 record := filepath.Join(t.TempDir(), "record")
 fake := "#!/bin/sh\nprintf '%s\\n' \"$PWD\" \"$@\" > \"$DISPATCH_RECORD\"\n"
 if err := os.WriteFile(filepath.Join(fakeBin, "go"), []byte(fake), 0700); err != nil { t.Fatal(err) }
 t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
 t.Setenv("DISPATCH_RECORD", record)
 runTest(context.Background(), filepath.Join(repoRootDir, "integration-tests/docker/tests/ssh-exporter"), 12345, false, time.Minute)
 if selected != "" { t.Fatalf("SSH default enumeration selected unsafe %s runner", selected) }
 out, err := os.ReadFile(record)
 if err != nil { t.Fatalf("isolated Go runner was not invoked: %v", err) }
 for _, want := range []string{repoRootDir, "test", "-count=1", "-tags=alloyintegrationtests", "-timeout=1m0s", "./integration-tests/docker/tests/ssh-exporter"} {
  if !strings.Contains(string(out), want+"\n") { t.Fatalf("missing argument %q: %s", want, out) }
 }
 if len(logs) != 1 || logs[0].IsError || logs[0].TestDir != "ssh-exporter" { t.Fatalf("unexpected result: %+v", logs) }
 runTest(context.Background(), filepath.Join(t.TempDir(), "ssh-exporter"), 12345, false, time.Minute)
 if selected != "legacy" { t.Fatalf("unrelated same-basename scenario changed route: %s", selected) }
 runTest(context.Background(), "ordinary-case", 12345, false, time.Minute)
 if selected != "legacy" { t.Fatalf("ordinary scenario changed route: %s", selected) }
 runTest(context.Background(), "compose-case", 12345, false, time.Minute)
 if selected != "compose" { t.Fatalf("Compose scenario changed route: %s", selected) }
}
`
	for name, contents := range map[string]string{"go.mod": "module dispatchproof\n\ngo 1.26.1\n", "dispatch_test.go": source} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "test", "-v", "-timeout=30s", ".")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("real default dispatcher regression: %v\n%s", err, out)
	}
}
