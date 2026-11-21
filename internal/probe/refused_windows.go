//go:build windows

package probe

import (
	"errors"
	"syscall"
)

// wsaeconnrefused is WSAECONNREFUSED; Windows does not map it to syscall.ECONNREFUSED.
const wsaeconnrefused syscall.Errno = 10061

func isRefused(err error) bool {
	return errors.Is(err, wsaeconnrefused) || errors.Is(err, syscall.ECONNREFUSED)
}
