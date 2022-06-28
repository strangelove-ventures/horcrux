package signer

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	tmLog "github.com/tendermint/tendermint/libs/log"
	tmOS "github.com/tendermint/tendermint/libs/os"
	tmService "github.com/tendermint/tendermint/libs/service"
)

func RequireNotRunning(lockFilePath string) error {
	if _, err := os.Stat(lockFilePath); err != nil {
		if os.IsNotExist(err) {
			// lock file does not exist, can continue starting daemon
			// or performing other tasks that require horcrux daemon to be stopped.
			return nil
		}
		return fmt.Errorf("unexpected error while checking for existence of lock file at %s: %w", lockFilePath, err)
	}

	lockFile, err := os.ReadFile(lockFilePath)
	if err != nil {
		return fmt.Errorf("error reading lock file: %s, %w", lockFilePath, err)
	}

	trimmed := strings.TrimSpace(string(lockFile))

	pid, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil {
		return fmt.Errorf("unexpected error parsing PID from lock file: %s. manual deletion of lockfile required. %w", lockFilePath, err)
	}

	_, err = os.FindProcess(int(pid))
	if err != nil {
		return fmt.Errorf("unclean shutdown detected. lockfile exists at %s but PID %d is not running. manual deletion of lockfile required. %w", lockFilePath, pid, err)
	}

	return fmt.Errorf("horcrux is already running on PID: %d", pid)
}

func WaitAndTerminate(logger tmLog.Logger, services []tmService.Service, lockFilePath string) {
	wg := sync.WaitGroup{}
	wg.Add(1)

	err := os.WriteFile(
		lockFilePath,
		[]byte(fmt.Sprintf("%d\n", os.Getpid())),
		0600,
	)
	if err != nil {
		panic(fmt.Errorf("error writing to lock file: %s. %w", lockFilePath, err))
	}
	tmOS.TrapSignal(logger, func() {
		if err := os.Remove(lockFilePath); err != nil {
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
