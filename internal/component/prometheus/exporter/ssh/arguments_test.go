package ssh

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/sshrunner"
	"github.com/grafana/alloy/internal/component/discovery"
	"github.com/grafana/alloy/syntax"
	"github.com/grafana/alloy/syntax/alloytypes"
	"github.com/grafana/alloy/syntax/parser"
	"github.com/grafana/alloy/syntax/vm"
)

func TestInlineKnownHostsDecode(t *testing.T) {
	var args Arguments
	require.NoError(t, syntax.Unmarshal([]byte(`
known_hosts = "inline trust"
auth "default" {
  username = "reader"
  password = "test-only"
}
`), &args))
	require.NoError(t, args.Validate())
	require.Equal(t, "inline trust", args.poolConfig().KnownHosts)
	require.False(t, args.KnownHosts.IsSecret)
}

func TestKnownHostsProducers(t *testing.T) {
	for _, producer := range []any{"inline trust", alloytypes.Secret("inline trust")} {
		t.Run(fmt.Sprintf("%T", producer), func(t *testing.T) {
			file, err := parser.ParseFile("", []byte(`
known_hosts = producer
auth "default" {
  username = "reader"
  password = "test-only"
}
`))
			require.NoError(t, err)
			var args Arguments
			require.NoError(t, vm.New(file).Evaluate(vm.NewScope(map[string]any{"producer": producer}), &args))
			require.NoError(t, args.Validate())
			require.Equal(t, "inline trust", args.poolConfig().KnownHosts)
			_, secret := producer.(alloytypes.Secret)
			require.Equal(t, secret, args.KnownHosts.IsSecret)
		})
	}
}

func TestInlineKnownHostsSizeLimit(t *testing.T) {
	var args Arguments
	args.SetToDefault()
	args.Auths = []Auth{{Name: "default", Username: "reader", Password: "test-only"}}
	args.KnownHosts.Value = strings.Repeat("#", (4<<20)+1)
	pool, err := sshrunner.New(args.poolConfig(), nil, nil)
	require.Nil(t, pool)
	require.EqualError(t, err, "sshrunner: known_hosts content exceeds 4 MiB")
}

func TestPoolConfigTargetMembership(t *testing.T) {
	for _, tc := range []struct {
		name string
		args Arguments
		want []agentless.Target
	}{
		{
			name: "blocks",
			args: Arguments{Targets: []Target{{Name: "one", Address: "host", Auth: "reader", Labels: map[string]string{"env": "test"}}, {Address: "[::1]:2222"}}},
			want: []agentless.Target{{Address: "host", Auth: "reader"}, {Address: "[::1]:2222", Auth: "default"}},
		},
		{
			name: "discovery",
			args: Arguments{Auths: []Auth{{Name: "default", Username: "reader", Password: "test-only"}}, TargetsList: []discovery.Target{discovery.NewTargetFromMap(map[string]string{"__address__": "host:2222", "name": "one"}), discovery.NewTargetFromMap(map[string]string{"address": "other"})}},
			want: []agentless.Target{{Address: "host:2222", Auth: "default"}, {Address: "other", Auth: "default"}},
		},
		{name: "empty", want: []agentless.Target{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.args.poolConfig()
			require.NotNil(t, cfg.Targets, "empty component membership must prune all destinations, not allow any")
			require.Equal(t, tc.want, cfg.Targets)
		})
	}
}
