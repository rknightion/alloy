//go:build !unix

package sshrunner

import (
	"errors"
	"os"
)

func openKnownHosts(string) (*os.File, error) {
	return nil, errors.New("sshrunner: safe known_hosts loading requires a Unix platform")
}
