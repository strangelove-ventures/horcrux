package signer

import (
	"sync"

	tmLog "github.com/tendermint/tendermint/libs/log"
	tmOS "github.com/tendermint/tendermint/libs/os"
	tmService "github.com/tendermint/tendermint/libs/service"
)

func WaitAndTerminate(logger tmLog.Logger, services []tmService.Service) {
	wg := sync.WaitGroup{}
	wg.Add(1)
	tmOS.TrapSignal(logger, func() {
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
