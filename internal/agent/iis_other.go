//go:build !windows

package agent

import "os"

func newWinHost() winHost { return nil }

func makeStateDir(dir string) error { return os.MkdirAll(dir, 0o700) }
