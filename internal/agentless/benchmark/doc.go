// Package benchmark contains an opt-in loopback SSH scale and fault harness.
// The farm and benchmark require the sshscale build tag and are absent from
// ordinary tests. Run BenchmarkSSHScale explicitly with -benchtime=1x and a
// bounded -timeout; it holds at least 500 real SSH connections and measures
// three scrape rounds scheduled 60 seconds apart. No Alloy server is launched.
package benchmark
