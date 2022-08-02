package signer

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	tmLog "github.com/tendermint/tendermint/libs/log"
	tmOS "github.com/tendermint/tendermint/libs/os"
	tmService "github.com/tendermint/tendermint/libs/service"
)

func RequireNotRunning(pidFilePath string) error {
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
		return fmt.Errorf(`unclean shutdown detected. PID file exists at %s but PID %d can not be found.
manual deletion of PID file required. %w`, pidFilePath, pid, err)
	}

	err = process.Signal(syscall.Signal(0))
	if err == nil {
		return fmt.Errorf("horcrux is already running on PID: %d", pid)
	}
	if errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf(`unclean shutdown detected. PID file exists at %s but PID %d is not running.
manual deletion of PID file required`, pidFilePath, pid)
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

func WaitAndTerminate(logger tmLog.Logger, services []tmService.Service, pidFilePath string) {
	wg := sync.WaitGroup{}
	wg.Add(1)

	pidFile, err := os.OpenFile(pidFilePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		panic(fmt.Errorf("error opening PID file: %s. %w", pidFilePath, err))
	}
	_, err = pidFile.Write([]byte(fmt.Sprintf("%d\n", os.Getpid())))
	pidFile.Close()
	if err != nil {
		panic(fmt.Errorf("error writing to lock file: %s. %w", pidFilePath, err))
	}
	tmOS.TrapSignal(logger, func() {
		if err := os.Remove(pidFilePath); err != nil {
			fmt.Printf("Error removing lock file: %v\n", err)
		}
		for _, service := range services {
			err := service.Stop()
			if err != nil {
				panic(err)
			}
		}
		wg.Done()
	})
	wg.Wait()
}
