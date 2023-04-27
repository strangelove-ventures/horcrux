package signer_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	cometlog "github.com/cometbft/cometbft/libs/log"
	cometservice "github.com/cometbft/cometbft/libs/service"
	"github.com/strangelove-ventures/horcrux/signer"

	fork "github.com/kraken-hpc/go-fork"
	"github.com/stretchr/testify/require"
)

func init() {
	fork.RegisterFunc("child", mockHorcruxChildProcess)
	fork.Init()
}

func mockHorcruxChildProcess(pidFilePath string) {
	_ = os.WriteFile(
		pidFilePath,
		[]byte(fmt.Sprintf("%d\n", os.Getpid())),
		0600,
	)
}

func waitForFileToExist(file string, timeout time.Duration) error {
	exp := time.After(timeout)
	tick := time.Tick(20 * time.Millisecond)
	for {
		select {
		case <-exp:
			return fmt.Errorf("timed out")
		case <-tick:
			if _, err := os.Stat(file); err != nil {
				if os.IsNotExist(err) {
					// file does not exist yet
					continue
				}
				// unexpected error
				return err
			}
			// file exists
			return nil
		}
	}
}

func TestIsRunning(t *testing.T) {
	homeDir := t.TempDir()
	pidFilePath := filepath.Join(homeDir, "horcrux.pid")

	// github.com/kraken-hpc/go-fork package used (in tests only) to create a new pid with args[0] of horcrux.
	// This lets us mock a horcrux process to test the "horcrux is already running" case.
	err := fork.Fork("child", pidFilePath)
	require.NoError(t, err)

	// wait for child process to start and write pidFilePath
	err = waitForFileToExist(pidFilePath, 1*time.Second)
	require.NoError(t, err)

	pidBz, err := os.ReadFile(pidFilePath)
	require.NoError(t, err)

	err = signer.RequireNotRunning(pidFilePath)
	expectedErrorMsg := fmt.Sprintf("horcrux is already running on PID: %s", strings.TrimSpace(string(pidBz)))
	require.EqualError(t, err, expectedErrorMsg)
}

func TestIsNotRunning(t *testing.T) {
	homeDir := t.TempDir()
	pidFilePath := filepath.Join(homeDir, "horcrux.pid")

	err := signer.RequireNotRunning(pidFilePath)
	require.NoError(t, err)
}

func getNonExistentPid() (int, error) {
	maxPidBytes, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		return -1, err
	}
	maxPid, err := strconv.ParseUint(strings.TrimSpace(string(maxPidBytes)), 10, 64)
	if err != nil {
		return -1, err
	}
	for pid := 1; pid <= int(maxPid); pid++ {
		process, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		err = process.Signal(syscall.Signal(0))
		if err == nil {
			continue
		}
		if errors.Is(err, os.ErrProcessDone) {
			return pid, nil
		}
		errno, ok := err.(syscall.Errno)
		if !ok {
			continue
		}
		if errno == syscall.ESRCH {
			return pid, nil
		}
	}
	return -1, errors.New("could not find unused PID")
}

func TestIsRunningNonExistentPid(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("test only valid on Linux")
	}

	homeDir := t.TempDir()
	pidFilePath := filepath.Join(homeDir, "horcrux.pid")

	pid, err := getNonExistentPid()
	require.NoError(t, err)

	err = os.WriteFile(
		pidFilePath,
		[]byte(fmt.Sprintf("%d\n", pid)),
		0600,
	)
	require.NoError(t, err, "error writing pid file")

	err = signer.RequireNotRunning(pidFilePath)
	expectedErrorMsg := fmt.Sprintf(`unclean shutdown detected. PID file exists at %s but PID %d is not running.
manual deletion of PID file required`, pidFilePath, pid)
	require.EqualError(t, err, expectedErrorMsg)
}

func TestConcurrentStart(t *testing.T) {
	concurrentAttempts := 10

	homeDir := t.TempDir()
	pidFilePath := filepath.Join(homeDir, "horcrux.pid")

	var logger cometlog.Logger
	var services []cometservice.Service

	var wg sync.WaitGroup
	wg.Add(concurrentAttempts)
	doneCount := 0
	panicCount := 0
	var countMu sync.Mutex

	recoverFromPanic := func() {
		_ = recover()
		countMu.Lock()
		defer countMu.Unlock()
		panicCount++
		if panicCount == concurrentAttempts-1 {
			for doneCount < concurrentAttempts {
				doneCount++
				wg.Done()
			}
		}
	}

	for i := 0; i < concurrentAttempts; i++ {
		go func() {
			defer recoverFromPanic()
			signer.WaitAndTerminate(logger, services, pidFilePath)
			doneCount++
			wg.Done()
		}()
	}

	wg.Wait()

	require.FileExists(t, pidFilePath, "PID file does not exist")

	require.Equal(t, concurrentAttempts-1, panicCount, "did not panic")
}

func TestIsRunningAndWaitForService(t *testing.T) {
	homeDir := t.TempDir()
	pidFilePath := filepath.Join(homeDir, "horcrux.pid")

	var logger cometlog.Logger
	var services []cometservice.Service
	go func() { signer.WaitAndTerminate(logger, services, pidFilePath) }()

	// Wait for signer.WaitAndTerminate to create pidFile
	var err error
	for i := 0; i < 5; i++ {
		time.Sleep(1 * time.Millisecond)
		_, err = os.Stat(pidFilePath)
		if err == nil {
			break
		}
	}
	require.NoError(t, err, "PID file does not exist after max attempts")

	var errMsg string

	var wg sync.WaitGroup
	wg.Add(1)

	recoverFromPanic := func() {
		r := recover()
		errMsg = fmt.Sprint(r)
		wg.Done()
	}
	panicFunction := func() {
		defer recoverFromPanic()
		err = signer.RequireNotRunning(pidFilePath)
	}
	go panicFunction()
	wg.Wait()

	require.Equal(t, errMsg, fmt.Sprintf("error checking PID file: %s, PID: %d matches current process",
		pidFilePath, os.Getpid()))
}
