package task

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type Task struct {
	Name     string
	Interval time.Duration
	Execute  func() error
	Reload   func()
	Access   sync.RWMutex
	Running  bool
	Stop     chan struct{}
}

func (t *Task) Start(first bool) error {
	t.Access.Lock()
	if t.Running {
		t.Access.Unlock()
		return nil
	}
	t.Running = true
	t.Stop = make(chan struct{})
	t.Access.Unlock()
	go func() {
		timer := time.NewTimer(t.Interval)
		defer timer.Stop()
		if first {
			if err := t.ExecuteWithTimeout(); err != nil {
				return
			}
		}

		for {
			timer.Reset(t.Interval)
			select {
			case <-timer.C:
				// continue
			case <-t.Stop:
				return
			}

			if err := t.ExecuteWithTimeout(); err != nil {
				log.Errorf("Task %s execution error: %v", t.Name, err)
				return
			}
		}
	}()

	return nil
}

func (t *Task) ExecuteWithTimeout() error {
	timeout := min(3*t.Interval, 5*time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	done := make(chan error, 1)

	go func() {
		done <- t.Execute()
	}()

	select {
	case <-ctx.Done():
		log.Warnf("Task %s execution timed out after %v, will retry next cycle", t.Name, timeout)
		// Do NOT call Reload() here.
		// The timed-out goroutine is still running and may access core resources.
		// Reloading would tear down those resources, causing nil pointer panics
		// or "inbound manager is nil" errors. Instead, let the next periodic
		// execution retry naturally, which handles transient network issues.
		return nil
	case err := <-done:
		return err
	}
}

func (t *Task) safeStop() {
	t.Access.Lock()
	if t.Running {
		t.Running = false
		close(t.Stop)
	}
	t.Access.Unlock()
}

func (t *Task) Close() {
	t.safeStop()
	log.Warningf("Task %s stopped", t.Name)
}
