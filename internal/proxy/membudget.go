package proxy

import (
	"context"
	"sync"
)

// bufferFactor is the peak heap per byte of a body while it is buffered,
// decoded and redacted: measured at 6-11x (one long JSON string is the
// worst case), so 12 leaves a margin.
const bufferFactor = 12

// memBudget bounds the memory that buffered bodies may take at once. Each
// buffered body reserves bufferFactor times its size before it is read and
// releases it when done, so a few large bodies wait for each other while
// small ones (most API and MCP responses) run side by side. A nil budget
// means no memory limit is known: only max_concurrent_buffered applies.
type memBudget struct {
	mu    sync.Mutex
	total int64
	free  int64
	freed chan struct{} // closed and replaced whenever memory is released
}

func newMemBudget(total int64) *memBudget {
	return &memBudget{total: total, free: total, freed: make(chan struct{})}
}

// acquire waits until n bytes are free; n must be at most total.
func (b *memBudget) acquire(ctx context.Context, n int64) error {
	for {
		b.mu.Lock()
		if n <= b.free {
			b.free -= n
			b.mu.Unlock()
			return nil
		}
		freed := b.freed
		b.mu.Unlock()
		select {
		case <-freed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// clamp limits a reservation to the whole budget, which acquire needs to
// ever succeed.
func (b *memBudget) clamp(n int64) int64 {
	if n > b.total {
		return b.total
	}
	return n
}

// ctxBudget is the budget for one request: waits end with its context.
type ctxBudget struct {
	mem *memBudget
	ctx context.Context
}

func (c ctxBudget) Acquire(n int64) error { return c.mem.acquire(c.ctx, c.mem.clamp(n)) }
func (c ctxBudget) Release(n int64)       { c.mem.release(c.mem.clamp(n)) }

func (b *memBudget) release(n int64) {
	b.mu.Lock()
	b.free += n
	close(b.freed)
	b.freed = make(chan struct{})
	b.mu.Unlock()
}

// SetMemoryLimit sizes response buffering to the process's memory limit in
// bytes (the container's). Buffered bodies may take three quarters of it
// together; the rest is for everything else. If a body of max_body_bytes
// couldn't fit even alone, bodies are capped lower. It returns the largest
// body that will be buffered.
func (s *Server) SetMemoryLimit(limit int64) int64 {
	if limit <= 0 {
		return s.maxBuffered
	}
	total := limit / 4 * 3
	s.mem = newMemBudget(total)
	// Request bodies are held until the response is done, so they get a
	// budget of their own: holding one while waiting for a response
	// reservation can then never starve the other.
	s.reqMem = newMemBudget(limit / 8)
	if fit := total / bufferFactor; fit < s.maxBuffered {
		s.maxBuffered = fit
	}
	return s.maxBuffered
}
