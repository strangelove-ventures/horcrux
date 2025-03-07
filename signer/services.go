package signer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

func RequireNotRunning(log *slog.Logger, pidFilePath string) error {
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
			"Unclean shutdown detected. PID file exists at but process with that ID cannot be found. Removing lock file",
			"pid", pid,
			"pid_file", pidFilePath,
			"error", err,
		)
		if err := os.Remove(pidFilePath); err != nil {
			return fmt.Errorf("failed to delete pid file %s: %w", pidFilePath, err)
		}
		return nil
	}

	errno, ok := err.(syscall.Errno)
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

func WaitAndTerminate(logger *slog.Logger, cancel context.CancelFunc, pidFilePath string) {
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

	TrapSignal(logger, func() {
		if err := os.Remove(pidFilePath); err != nil {
			fmt.Printf("Error removing lock file: %v\n", err)
		}
		cancel()
		close(done)
	})
	<-done
}

// TrapSignal catches the SIGTERM/SIGINT and executes cb function. After that it exits
// with code 0.
func TrapSignal(logger *slog.Logger, cb func()) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		for sig := range c {
			logger.Info("signal trapped", "msg", fmt.Sprintf("captured %v, exiting...", sig))
			if cb != nil {
				cb()
			}
			os.Exit(0)
		}
	}()
}
