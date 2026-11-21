//go:build !windows

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
)

func defaultConfigPath() string { return "/etc/certloom-agent/config.yaml" }

func isService() bool { return false }

func serviceLog(string) (*slog.Logger, io.Closer, error) {
	return nil, nil, errors.New("not a service")
}

func runService(func(context.Context) error) error { return errors.New("not a service") }

func serviceCommand(string, string) error {
	return errors.New("service install is for Windows; use the systemd unit from the package on Linux")
}
