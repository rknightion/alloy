package batch

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/stretchr/testify/require"
)

const testNonce = "0123456789abcdef0123456789abcdef"

func fixtureReads() []agentless.Read {
	return []agentless.Read{agentless.CommandRead("printf", "hello"), agentless.CommandRead("false"), agentless.FileRead("/batch-missing-file"), agentless.CommandRead("printf", "tail")}
}

func TestBuild(t *testing.T) {
	nonce, err := NewNonce()
	require.NoError(t, err)
	require.Regexp(t, "^[0-9a-f]{32}$", nonce)
	other, err := NewNonce()
	require.NoError(t, err)
	require.NotEqual(t, nonce, other)
	read := agentless.CommandRead("printf", "hello")
	read.ID = "never-embed;unsafe"
	script, err := Build([]agentless.Read{read}, nonce)
	require.NoError(t, err)
	require.NotContains(t, script, read.ID)
	_, err = Build([]agentless.Read{agentless.CommandRead("echo", "bad;value")}, nonce)
	require.Error(t, err)
	_, err = Build(nil, "bad")
	require.Error(t, err)
}

func TestRecordedShells(t *testing.T) {
	for _, shell := range []string{"dash", "busybox"} {
		t.Run(shell, func(t *testing.T) {
			output, err := os.ReadFile("testdata/" + shell + ".out")
			require.NoError(t, err)
			results, err := Demux(context.Background(), strings.NewReader(string(output)), testNonce, fixtureReads(), DefaultLimits)
			require.NoError(t, err)
			require.Len(t, results, 4)
			require.Equal(t, "hello", string(results[0].Output))
			require.Equal(t, 1, results[1].ExitStatus)
			require.True(t, results[2].NotExist)
			require.Equal(t, "tail", string(results[3].Output))
		})
	}
}

func TestFramingAndLimits(t *testing.T) {
	reads := []agentless.Read{agentless.CommandRead("printf", "hello")}
	payload := "hello\nffffffffffffffffffffffffffffffff:0:end:0:0\nno-final-newline"
	framed := testNonce + ":0:begin\n" + payload + "\n" + testNonce + ":0:end:0:0\n"
	results, err := Demux(context.Background(), strings.NewReader(framed), testNonce, reads, Limits{MaxSectionBytes: 5, MaxOutputBytes: 4096})
	require.NoError(t, err)
	require.Equal(t, "hello", string(results[0].Output))
	require.True(t, results[0].Truncated)
	results, err = Demux(context.Background(), strings.NewReader(framed), testNonce, reads, DefaultLimits)
	require.NoError(t, err)
	require.Equal(t, payload, string(results[0].Output))
	_, err = Demux(context.Background(), strings.NewReader(framed), testNonce, reads, Limits{MaxSectionBytes: 5, MaxOutputBytes: 10})
	require.Error(t, err)
	_, err = Demux(context.Background(), strings.NewReader("garbage\n"), testNonce, reads, DefaultLimits)
	require.Error(t, err)
}

type stalledReader struct{ ctx context.Context }

func (r stalledReader) Read([]byte) (int, error) { <-r.ctx.Done(); return 0, r.ctx.Err() }

func TestStreamingDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	go func() {
		_, _ = io.WriteString(writer, testNonce+":0:begin\nhello\n"+testNonce+":0:end:0:0\n"+testNonce+":1:begin\npartial")
	}()
	results, err := Demux(ctx, reader, testNonce, fixtureReads(), DefaultLimits)
	require.NoError(t, err)
	require.Equal(t, "hello", string(results[0].Output))
	require.False(t, results[0].TimedOut)
	require.Equal(t, "partial", string(results[1].Output))
	require.True(t, results[1].TimedOut)
	require.True(t, results[3].TimedOut)
}

func TestLargeOutput(t *testing.T) {
	reads := fixtureReads()[:1]
	output := testNonce + ":0:begin\n" + strings.Repeat("x", 100000) + "\n" + testNonce + ":0:end:0:0\n"
	results, err := Demux(context.Background(), strings.NewReader(output), testNonce, reads, Limits{MaxSectionBytes: 8, MaxOutputBytes: 200000})
	require.NoError(t, err)
	require.Equal(t, "xxxxxxxx", string(results[0].Output))
	require.True(t, results[0].Truncated)
	for _, status := range []string{"256:0", "0:1", "1:2", "x:0"} {
		_, err = Demux(context.Background(), strings.NewReader(testNonce+":0:begin\n\n"+testNonce+":0:end:"+status+"\n"), testNonce, reads, DefaultLimits)
		require.Error(t, err)
	}
}

func TestFirstSectionPartial(t *testing.T) {
	results, err := Demux(context.Background(), strings.NewReader(testNonce+":0:begin\npartial"), testNonce, fixtureReads(), DefaultLimits)
	require.NoError(t, err)
	require.Equal(t, "partial", string(results[0].Output))
	require.True(t, results[0].TimedOut)
}

func TestDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := Demux(ctx, stalledReader{ctx}, testNonce, fixtureReads(), DefaultLimits)
	require.Error(t, err)
	prefix := testNonce + ":0:begin\nhello\n" + testNonce + ":0:end:0:0\n" + testNonce + ":1:begin\npartial"
	results, err := Demux(context.Background(), strings.NewReader(prefix), testNonce, fixtureReads(), DefaultLimits)
	require.NoError(t, err)
	require.False(t, results[0].TimedOut)
	require.True(t, results[1].TimedOut)
	require.Equal(t, "partial", string(results[1].Output))
	require.True(t, results[3].TimedOut)
}
