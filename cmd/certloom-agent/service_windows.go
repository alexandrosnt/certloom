package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "certloom-agent"

func defaultConfigPath() string {
	return filepath.Join(os.Getenv("ProgramData"), "certloom-agent", "config.yaml")
}

func isService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// serviceLog writes JSON logs next to the config: a service has no console.
// The file is started over when it passes 10 MB.
func serviceLog(cfgPath string) (*slog.Logger, io.Closer, error) {
	path := filepath.Join(filepath.Dir(cfgPath), "agent.log")
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if fi, err := os.Stat(path); err == nil && fi.Size() > 10<<20 {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return slog.New(slog.NewJSONHandler(f, nil)), f, nil
}

type agentService struct {
	run func(context.Context) error
}

func (s *agentService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			cancel()
			if err != nil {
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case err := <-done:
					if err != nil {
						return true, 1
					}
				case <-time.After(20 * time.Second):
				}
				return false, 0
			}
		}
	}
}

func runService(run func(context.Context) error) error {
	return svc.Run(serviceName, &agentService{run: run})
}

// serviceCommand installs or removes the Windows service. The service runs
// as LocalSystem, which HTTP.sys configuration and machine keys require
// (ADR-0022), and restarts after a crash.
func serviceCommand(action, cfgPath string) error {
	if action != "install" && action != "uninstall" {
		return errors.New("usage: certloom-agent service install|uninstall [--config FILE]")
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect() //nolint:errcheck // best effort
	switch action {
	case "install":
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if s, err := m.OpenService(serviceName); err == nil {
			_ = s.Close()
			return errors.New("service already installed")
		}
		s, err := m.CreateService(serviceName, exe, mgr.Config{DisplayName: "certloom agent", StartType: mgr.StartAutomatic,
			Description: "Renews and installs TLS certificates for the certloom control plane."}, "run", "--config", cfgPath)
		if err != nil {
			return err
		}
		defer s.Close() //nolint:errcheck // handle close after the change is done
		if err := s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
			{Type: mgr.ServiceRestart, Delay: time.Minute}, {Type: mgr.ServiceRestart, Delay: 5 * time.Minute}}, 86400); err != nil {
			return err
		}
		fmt.Printf("Installed service %s (config %s). Start it with: sc.exe start %s\n", serviceName, cfgPath, serviceName)
		return nil
	case "uninstall":
		s, err := m.OpenService(serviceName)
		if err != nil {
			return errors.New("service not installed")
		}
		defer s.Close() //nolint:errcheck // handle close after the change is done
		_, _ = s.Control(svc.Stop)
		return s.Delete()
	}
	return nil
}
