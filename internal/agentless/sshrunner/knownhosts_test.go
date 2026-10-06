package sshrunner

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKnownHostsSizeLimit(t *testing.T) {
	host, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	cfg := configFor(t, s, host.PublicKey())
	// Valid comments avoid confusing a parser error with size enforcement.
	require.NoError(t, os.WriteFile(cfg.KnownHostsFiles[0], bytes.Repeat([]byte("# bounded comment\n"), 310000), 0600))
	_, err := New(cfg, nil, nil)
	require.ErrorContains(t, err, "4 MiB")
}
