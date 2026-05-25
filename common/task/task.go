package task

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

type Task struct {
	Name      string
	Interval  time.Duration
	Execute   func(context.Context) error
	ReloadCh  chan struct{} // 超时时触发主服务重启
	Access    sync.RWMutex
	Running   bool
	Stop      chan struct{}
	executing atomic.Bool // prevents overlapping executions
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
	// Skip if previous execution is still running (goroutine leaked from last timeout).
	// This prevents goroutine accumulation, which causes lock contention
	// and cascading timeouts across all nodes.
	if !t.executing.CompareAndSwap(false, true) {
		log.Debugf("Task %s: previous execution still running, skipping this cycle", t.Name)
		return nil
	}

	timeout := min(5*t.Interval, 5*time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	done := make(chan error, 1)

	go func() {
		done <- t.Execute(ctx)
		t.executing.Store(false)
	}()

	select {
	case <-ctx.Done():
		log.Errorf("Task %s execution timed out after %v, triggering service reload", t.Name, timeout)
		
		// Dump stack trace to identify where the task is stuck
		// Added: Dump stack trace to local file
		dumpFile := fmt.Sprintf("v2node_timeout_%s_%s.log", t.Name, time.Now().Format("20060102_150405"))
		buf := make([]byte, 2*1024*1024) // 2MB
		n := runtime.Stack(buf, true)
		if err := os.WriteFile(dumpFile, buf[:n], 0644); err != nil {
			log.Errorf("Failed to dump stack trace to %s: %v", dumpFile, err)
		} else {
			log.Warnf("Stack trace of all goroutines dumped to %s", dumpFile)
		}

		// 超时后触发主服务重启（看门狗机制），让xray重新加载用户列表
		if t.ReloadCh != nil {
			select {
			case t.ReloadCh <- struct{}{}:
			default:
				// 通道已满，说明reload已经在队列中
			}
		} else {
			log.Panicf("Task %s: ReloadCh is nil, cannot trigger reload", t.Name)
		}
		return nil
	case err := <-done:
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
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

