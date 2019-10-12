package goflyway

import (
	"net"
	"strings"
	"sync"
	"time"
)

func isClosedConnErr(err error) bool {
	return strings.Contains(err.Error(), "use of closed")
}

func isTimeoutErr(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}

	return false
}

type TokenBucket struct {
	Speed int64 // bytes per second

	capacity    int64 // bytes
	maxCapacity int64
	lastConsume time.Time

	mu sync.Mutex
}

func NewTokenBucket(speed, max int64) *TokenBucket {
	return &TokenBucket{
		Speed:       speed,
		lastConsume: time.Now(),
		maxCapacity: max,
	}
}

func (tb *TokenBucket) Consume(n int64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()

	if tb.Speed == 0 {
		tb.lastConsume = now
		return
	}

	ms := now.Sub(tb.lastConsume).Nanoseconds() / 1e6
	tb.capacity += ms * tb.Speed / 1000

	if tb.capacity > tb.maxCapacity {
		tb.capacity = tb.maxCapacity
	}

	if n <= tb.capacity {
		tb.lastConsume = now
		tb.capacity -= n
		return
	}

	sec := float64(n-tb.capacity) / float64(tb.Speed)
	time.Sleep(time.Duration(sec*1000) * time.Millisecond)

	tb.capacity = 0
	tb.lastConsume = time.Now()
}

type Traffic struct {
	sent     int64
	received int64
}

func (t *Traffic) Set(s, r int64) {
	t.sent, t.received = s, r
}

func (t *Traffic) Sent() *int64 {
	if t == nil {
		return nil
	}
	return &t.sent
}

func (t *Traffic) Recv() *int64 {
	if t == nil {
		return nil
	}
	return &t.received
}
