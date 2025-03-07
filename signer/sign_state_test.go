package signer

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignStateCheck(t *testing.T) {
	filepath := t.TempDir() + "/sign_state.json"
	ss, err := LoadOrCreateSignState(filepath)
	require.NoError(t, err)
	require.NotNil(t, ss)

	for i := 1; i < 100; i++ {
		const jMax = 100
		startedCh := make(chan struct{}, jMax)
		workNowCh := make(chan struct{})

		numErr, numSuccess := 0, 0
		var mu sync.Mutex
		i := i
		var wg sync.WaitGroup
		wg.Add(100)
		for j := 0; j < jMax; j++ {
			go func() {
				startedCh <- struct{}{} // Notify reader that goroutine is ready to run.
				<-workNowCh             // Coordinator closes this channel so all goroutines can start working.

				defer wg.Done()
				err := ss.Save(SignStateConsensus{
					Height: int64(i),
				}, nil)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					numErr++
				} else {
					numSuccess++
				}
			}()
		}

		for j := 0; j < jMax; j++ {
			<-startedCh // Make sure all goroutines are ready to run.
		}

		close(workNowCh) // Give them the start signal.
		wg.Wait()
		require.Equal(t, numSuccess, 1)
		require.Equal(t, numErr, 99)
	}
}

func TestSignStateCheckDiskWG(t *testing.T) {
	filepath := t.TempDir() + "/sign_state.json"
	ss, err := LoadOrCreateSignState(filepath)
	require.NoError(t, err)
	require.NotNil(t, ss)

	var pendingDiskWG sync.WaitGroup

	for i := 1; i < 100; i++ {
		const jMax = 100
		startedCh := make(chan struct{}, jMax)
		workNowCh := make(chan struct{})

		numErr, numSuccess := 0, 0
		var mu sync.Mutex
		i := i
		var wg sync.WaitGroup
		wg.Add(100)
		for j := 0; j < jMax; j++ {
			go func() {
				startedCh <- struct{}{} // Notify reader that goroutine is ready to run.
				<-workNowCh             // Coordinator closes this channel so all goroutines can start working.

				defer wg.Done()
				err := ss.Save(SignStateConsensus{
					Height: int64(i),
				}, &pendingDiskWG)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					numErr++
				} else {
					numSuccess++
				}
			}()
		}

		for j := 0; j < jMax; j++ {
			<-startedCh // Make sure all goroutines are ready to run.
		}

		close(workNowCh) // Give them the start signal.
		wg.Wait()
		pendingDiskWG.Wait()

		require.Equal(t, numSuccess, 1)
		require.Equal(t, numErr, 99)
	}
}
