package signer

import (
	"os"
	"sync"

	tmLog "github.com/tendermint/tendermint/libs/log"
	tmOS "github.com/tendermint/tendermint/libs/os"
	tmService "github.com/tendermint/tendermint/libs/service"
)

func WaitAndTerminate(logger tmLog.Logger, services []tmService.Service, lockFilePath string) {
	wg := sync.WaitGroup{}
	wg.Add(1)

	file, err := os.Create(lockFilePath)
	if err != nil {
		panic(err)
	}
	file.Close()
	defer tmOS.TrapSignal(logger, func() {
		_ = os.Remove(lockFilePath)
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
