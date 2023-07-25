package cond

import (
	"sync"
	"sync/atomic"
	"time"
)

// Inspired by https://gist.github.com/zviadm/c234426882bfc8acba88f3503edaaa36#file-cond2-go
// Similar to sync.Cond, but supports timeout based Wait() calls.

// Cond is a conditional variable implementation that uses channels for notifications.
// It only supports .Broadcast() method, however supports timeout based Wait() calls
// unlike regular sync.Cond.
type Cond struct {
	L sync.Locker
	p atomic.Pointer[chan struct{}]
}

func New(l sync.Locker) *Cond {
	c := &Cond{
		L: l,
		p: atomic.Pointer[chan struct{}]{},
	}
	n := make(chan struct{})
	c.p.Store(&n)
	return c
}

// Wait waits for Broadcast calls. Similar to regular sync.Cond, this unlocks the underlying
// locker first, waits on changes and re-locks it before returning.
func (c *Cond) Wait() {
	n := c.NotifyChan()
	c.L.Unlock()
	<-n
	c.L.Lock()
}

// WaitWithTimeout is same as Wait() call, but will only wait up to a given timeout.
func (c *Cond) WaitWithTimeout(t time.Duration) {
	tm := time.NewTimer(t)
	defer tm.Stop()
	n := c.NotifyChan()
	c.L.Unlock()
	select {
	case <-n:
	case <-tm.C:
	}
	c.L.Lock()
}

// NotifyChan returns a channel that can be used to wait for next Broadcast() call.
func (c *Cond) NotifyChan() <-chan struct{} {
	ptr := c.p.Load()
	return *ptr
}

// Broadcast notifies all waiting goroutines that something has changed.
func (c *Cond) Broadcast() {
	n := make(chan struct{})
	p := c.p.Swap(&n)
	close(*p)
}
