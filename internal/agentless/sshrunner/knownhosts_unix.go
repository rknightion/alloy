//go:build unix

package sshrunner

import (
	"os"

	"golang.org/x/sys/unix"
)

func openKnownHosts(name string) (*os.File, error) {
	return os.OpenFile(name, os.O_RDONLY|unix.O_NONBLOCK, 0)
}
