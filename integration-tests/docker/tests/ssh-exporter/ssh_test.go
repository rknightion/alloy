//go:build alloyintegrationtests && !nodocker

package ssh_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestOpenSSH exercises the built Linux CLI, public configuration, HTTP handler,
// persistent sessions and mandatory known_hosts verification against OpenSSH on
// Alpine's BusyBox userspace. No ports, shared networks or named volumes are used.
func TestOpenSSH(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	run := func(name string, args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, name, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return string(out)
	}
	id := fmt.Sprintf("ssh-exporter-%x", randomID(t))
	image := id + ":test"
	dir := t.TempDir()
	binary := filepath.Join(dir, "alloy")
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "go", "build", "-tags=gore2regex", "-o", binary, ".")
	cmd.Dir = filepath.Join(root, "collector")
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=go1.26.7", "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build Linux Alloy: %v\n%s", err, out)
	}
	run("docker", "build", "-t", image, ".")
	cleanup := func(args ...string) {
		cleanupCtx, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		out, err := exec.CommandContext(cleanupCtx, "docker", args...).CombinedOutput()
		if err != nil {
			t.Errorf("cleanup %v: %v\n%s", args, err, out)
		}
	}
	t.Cleanup(func() { cleanup("image", "rm", image) })
	container := strings.TrimSpace(run("docker", "create", "--name", id, "--mount", "type=bind,src="+dir+",dst=/test", image, "sleep", "infinity"))
	// Register only after successful creation, and clean up by immutable ID.
	t.Cleanup(func() { cleanup("rm", "-f", container) })
	run("docker", "start", container)
	// Copy into the container filesystem: host temporary mounts may be noexec.
	run("docker", "cp", binary, container+":/usr/local/bin/alloy")
	run("docker", "exec", container, "chmod", "755", "/usr/local/bin/alloy")
	sh := func(script string) string {
		t.Helper()
		return run("docker", "exec", container, "sh", "-ec", script)
	}
	sh(`ssh-keygen -q -t ed25519 -N '' -f /test/client
ssh-keygen -q -t ed25519 -N '' -f /test/host
printf 'restrict ' > /home/collector/.ssh/authorized_keys
cat /test/client.pub >> /home/collector/.ssh/authorized_keys
chown -R collector:collector /home/collector/.ssh
chmod 600 /home/collector/.ssh/authorized_keys
printf 'localhost ' > /test/known_hosts
cat /test/host.pub >> /test/known_hosts
cat > /test/sshd_config <<'EOF'
Port 22
ListenAddress 127.0.0.1
HostKey /test/host
PidFile /test/sshd.pid
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers collector
LogLevel VERBOSE
EOF
/usr/sbin/sshd -f /test/sshd_config -E /test/sshd.log`)
	config := `local.file "key" {
  filename = "/test/client"
  is_secret = true
}
prometheus.exporter.ssh "test" {
  auth "default" {
    username = "collector"
    private_key = local.file.key.content
  }
  known_hosts_files = ["/test/known_hosts"]
  target "busybox" {
    address = "localhost:22"
  }
  enabled_collectors = ["cpu", "stat", "meminfo", "loadavg", "uname"]
  dial_timeout = "1s"
  timeout = "3s"
}
`
	if err := os.WriteFile(filepath.Join(dir, "config.alloy"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	startAlloy := func() {
		t.Helper()
		run("docker", "exec", "-d", container, "sh", "-ec", `exec /usr/local/bin/alloy run /test/config.alloy --stability.level=experimental --disable-reporting --server.http.listen-addr=127.0.0.1:12345 --storage.path=/test/data > /test/alloy.log 2>&1`)
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			out := sh(`curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:12345/-/ready || true`)
			if out == "200" {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatalf("Alloy readiness timeout: %s", sh("cat /test/alloy.log"))
	}
	scrape := func(target string) string {
		t.Helper()
		return run("docker", "exec", container, "curl", "-sS", "--max-time", "5", "-w", "\n%{http_code}", "http://127.0.0.1:12345/api/v0/component/prometheus.exporter.ssh.test/metrics?target="+target)
	}
	good := func(out string) {
		t.Helper()
		if !strings.HasSuffix(out, "\n200") {
			t.Fatalf("expected successful SSH scrape, got %s", out)
		}
		for _, metric := range []string{"node_cpu_seconds_total{", "node_memory_MemTotal_bytes ", "node_load1 ", "node_uname_info{", `node_scrape_collector_success{collector="cpu"} 1`} {
			if !strings.Contains(out, metric) {
				t.Fatalf("missing metric %q: %s", metric, out)
			}
		}
	}
	startAlloy()
	good(scrape("localhost:22"))
	good(scrape("localhost:22")) // Reuse the real transport/session pool.
	if out := scrape("localhost:23"); !strings.HasSuffix(out, "\n400") || !strings.Contains(out, "unknown target") {
		t.Fatalf("unconfigured target was not rejected: %s", out)
	}
	// OpenSSH changes child process titles; match their anchored titles,
	// including sshd-session children, only inside our private container.
	stopSSHD := func() {
		t.Helper()
		sh(`pkill -KILL -f '^sshd' || true`)
	}
	stopSSHD()
	out := scrape("localhost:22")
	t.Logf("stopped sshd: %s", out)
	if os.Getenv("SSH_EXPORTER_RED") == "stopped" {
		good(out) // Fault injection must break the same positive metric oracle.
	}
	if !strings.Contains(out, "SSH scrape failed") || !strings.HasSuffix(out, "\n503") {
		t.Fatalf("stopped sshd did not fail the scrape: %s", out)
	}
	sh("/usr/sbin/sshd -f /test/sshd_config -E /test/sshd.log")
	// Restart Alloy to clear reconnect backoff; every invocation uses reporting
	// disabled and a loopback listener. Trust stays unchanged across the restart.
	sh("pkill -f '^/usr/local/bin/alloy run'")
	startAlloy()
	good(scrape("localhost:22"))
	stopSSHD()
	sh(`rm /test/host /test/host.pub
ssh-keygen -q -t ed25519 -N '' -f /test/host
/usr/sbin/sshd -f /test/sshd_config -E /test/sshd.log
pkill -f '^/usr/local/bin/alloy run'`)
	startAlloy()
	out = scrape("localhost:22")
	t.Logf("changed host key: %s", out)
	if !strings.Contains(out, "SSH scrape failed") || !strings.HasSuffix(out, "\n503") {
		t.Fatalf("changed host key did not fail closed: %s", out)
	}
	metrics := sh("curl -sS http://127.0.0.1:12345/metrics")
	found := false
	for _, line := range strings.Split(metrics, "\n") {
		if strings.HasPrefix(line, "agentless_ssh_host_key_failures_total{") && strings.HasSuffix(line, " 1") {
			found = true
			t.Logf("host-key verification evidence: %s", line)
		}
	}
	if !found {
		t.Fatalf("missing host-key rejection counter: %s", metrics)
	}
	if os.Getenv("SSH_EXPORTER_RED") == "hostkey" {
		good(out)
	}
	// Provision the new trust entry and prove the otherwise identical server works.
	sh("printf 'localhost ' > /test/known_hosts; cat /test/host.pub >> /test/known_hosts; pkill -f '^/usr/local/bin/alloy run'")
	startAlloy()
	good(scrape("localhost:22"))
}

func randomID(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
