package cond_test

import (
	"runtime"
	"sync"
	"testing"

	"github.com/strangelove-ventures/horcrux/src/cond"
	"github.com/stretchr/testify/require"
)

func TestRace(t *testing.T) {
	x := 0
	c := cond.New(&sync.Mutex{})
	done := make(chan bool)
	go func() {
		c.L.Lock()
		x = 1
		c.Wait()
		require.Equal(t, 2, x)
		x = 3
		c.Broadcast()
		c.L.Unlock()
		done <- true
	}()
	go func() {
		c.L.Lock()
		for {
			if x == 1 {
				x = 2
				c.Broadcast()
				break
			}
			c.L.Unlock()
			runtime.Gosched()
			c.L.Lock()
		}
		c.L.Unlock()
		done <- true
	}()
	go func() {
		c.L.Lock()
		for {
			if x == 2 {
				c.Wait()
				require.Equal(t, 3, x)
				break
			}
			if x == 3 {
				break
			}
			c.L.Unlock()
			runtime.Gosched()
			c.L.Lock()
		}
		c.L.Unlock()
		done <- true
	}()
	<-done
	<-done
	<-done
}
