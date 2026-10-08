package inspectionproduct

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// RuntimeGroup gives multiple genuine Start/Stop runtimes one ordered product
// lifecycle. Temporary observation processing does not belong here because it
// is a RunOnce processor owned by Product's lease-aware polling loop.
type RuntimeGroup struct {
	mu       sync.Mutex
	children []Runtime
	started  int
	closed   bool
}

func NewRuntimeGroup(children ...Runtime) (*RuntimeGroup, error) {
	if len(children) < 2 || len(children) > 16 {
		return nil, errors.New("inspection runtime group requires two to sixteen runtimes")
	}
	group := &RuntimeGroup{children: append([]Runtime(nil), children...)}
	for _, child := range group.children {
		if isNil(child) {
			return nil, errors.New("inspection runtime group contains a nil runtime")
		}
	}
	return group, nil
}

func (g *RuntimeGroup) Start(ctx context.Context) error {
	if g == nil || ctx == nil {
		return errors.New("inspection runtime group is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	g.mu.Lock()
	if g.closed || g.started != 0 {
		g.mu.Unlock()
		return errors.New("inspection runtime group lifecycle is already consumed")
	}
	for index, child := range g.children {
		if err := ctx.Err(); err != nil {
			started := g.started
			g.started = 0
			g.closed = true
			g.mu.Unlock()
			for previous := started - 1; previous >= 0; previous-- {
				g.children[previous].Stop()
			}
			return err
		}
		if err := child.Start(ctx); err != nil {
			// Runtime promises Stop is safe after a partially failed Start.
			started := g.started
			g.started = 0
			g.closed = true
			g.mu.Unlock()
			child.Stop()
			for previous := started - 1; previous >= 0; previous-- {
				g.children[previous].Stop()
			}
			return fmt.Errorf("start inspection runtime group child %d: %w", index, err)
		}
		g.started++
	}
	g.mu.Unlock()
	return nil
}

func (g *RuntimeGroup) Stop() {
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	started := g.started
	g.started = 0
	g.mu.Unlock()
	for index := started - 1; index >= 0; index-- {
		g.children[index].Stop()
	}
}
