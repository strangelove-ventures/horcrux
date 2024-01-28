package cmd

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	cometlog "github.com/cometbft/cometbft/libs/log"
	cometos "github.com/cometbft/cometbft/libs/os"
	cometservice "github.com/cometbft/cometbft/libs/service"
)

// TODO: Move RequireNotRunning outside of this package.
func RequireNotRunning(log cometlog.Logger, pidFilePath string) error {
	if _, err := os.Stat(pidFilePath); err != nil {
		if os.IsNotExist(err) {
			// lock file does not exist, can continue starting daemon
			// or performing other tasks that require horcrux daemon to be stopped.
			return nil
		}
		return fmt.Errorf("unexpected error while checking for existence of PID file at %s: %w", pidFilePath, err)
	}

	lockFile, err := os.ReadFile(pidFilePath)
	if err != nil {
		return fmt.Errorf("error reading lock file: %s, %w", pidFilePath, err)
	}

	pid, err := strconv.ParseInt(strings.TrimSpace(string(lockFile)), 10, 64)
	if err != nil {
		return fmt.Errorf("unexpected error parsing PID from PID file: %s. manual deletion of PID file required. %w",
			pidFilePath, err)
	}

	if int(pid) == os.Getpid() {
		panic(fmt.Errorf("error checking PID file: %s, PID: %d matches current process",
			pidFilePath, pid))
	}

	process, err := os.FindProcess(int(pid))
	if err != nil {
		return fmt.Errorf("error checking pid %d: %w", pid, err)
	}

	err = process.Signal(syscall.Signal(0))
	if err == nil {
		return fmt.Errorf("horcrux is already running on PID: %d", pid)
	}
	if errors.Is(err, os.ErrProcessDone) {
		log.Error(
			"Unclean shutdown detected. PID file exists at but process with that Index cannot be found. Removing lock file",
			"pid", pid,
			"pid_file", pidFilePath,
			"error", err,
		)
		if err := os.Remove(pidFilePath); err != nil {
			return fmt.Errorf("failed to delete pid file %s: %w", pidFilePath, err)
		}
		return nil
	}

	var errno syscall.Errno
	ok := errors.As(err, &errno)
	if !ok {
		return fmt.Errorf("unexpected error type from signaling horcrux PID: %d", pid)
	}
	switch errno {
	case syscall.ESRCH:
		return fmt.Errorf("search error while signaling horcrux PID: %d", pid)
	case syscall.EPERM:
		return fmt.Errorf("permission denied accessing horcrux PID: %d", pid)
	}
	return fmt.Errorf("unexpected error while signaling horcrux PID: %d", pid)
}

func WaitAndTerminate(logger cometlog.Logger, services []cometservice.Service, pidFilePath string) {
	done := make(chan struct{})

	pidFile, err := os.OpenFile(pidFilePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		panic(fmt.Errorf("error opening PID file: %s. %w", pidFilePath, err))
	}
	_, err = pidFile.Write([]byte(fmt.Sprintf("%d\n", os.Getpid())))
	pidFile.Close()
	if err != nil {
		panic(fmt.Errorf("error writing to lock file: %s. %w", pidFilePath, err))
	}
	cometos.TrapSignal(logger, func() {
		if err := os.Remove(pidFilePath); err != nil {
			fmt.Printf("Error removing lock file: %v\n", err)
		}
		for _, service := range services {
			err := service.Stop()
			if err != nil {
				panic(err)
			}
		}
		close(done)
	})
	<-done
}
