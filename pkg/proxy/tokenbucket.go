package proxy

import (
	"sync"
	"time"
)

/*
 * A variation of token bucket for traffic throttling
 * Note goflyway is intended for single user mainly, so throttling is really not that necessary for now
 * TODO: bugs all around
 */

type TokenBucket struct {
	Speed int64 // bytes per second

	capacity    int64 // bytes
	maxCapacity int64
	lastConsume int64

	mu sync.Mutex
}

func NewTokenBucket(speed, max int64) *TokenBucket {
	return &TokenBucket{
		Speed:       speed,
		lastConsume: time.Now().UnixNano(),
		maxCapacity: max,
	}
}

func (tb *TokenBucket) Consume(n int64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now().UnixNano()

	if tb.Speed == 0 {
		tb.lastConsume = now
		return
	}

	ms := (now - tb.lastConsume) / 1e6
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
	tb.lastConsume = time.Now().UnixNano()
}
