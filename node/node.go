package node

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	panel "github.com/xxntmctx/v2node/api/v2board"
	"github.com/xxntmctx/v2node/conf"
	"github.com/xxntmctx/v2node/core"
)

type Node struct {
	controllers []*Controller
	NodeInfos   []*panel.NodeInfo
	nodeConfigs []conf.NodeConfig
	v2core      *core.V2Core
	stopRetry   chan struct{}
}

func New(nodes []conf.NodeConfig) (*Node, error) {
	n := &Node{
		controllers: make([]*Controller, len(nodes)),
		NodeInfos:   make([]*panel.NodeInfo, len(nodes)),
		nodeConfigs: nodes,
	}
	for i, node := range nodes {
		p, err := panel.New(&node)
		if err != nil {
			return nil, err
		}
		info, err := p.GetNodeInfo()
		if err != nil {
			return nil, err
		}
		n.controllers[i] = NewController(p, &node, info)
		n.NodeInfos[i] = info
	}
	return n, nil
}

func (n *Node) Start(nodes []conf.NodeConfig, core *core.V2Core) error {
	n.v2core = core
	n.nodeConfigs = nodes
	var started int
	var hasFailed bool
	for i, node := range nodes {
		err := n.controllers[i].Start(core)
		if err != nil {
			log.WithFields(log.Fields{
				"host":    node.APIHost,
				"node_id": node.NodeID,
				"err":     err,
			}).Error("Start node controller failed, skipping this node")
			n.controllers[i] = nil // mark as failed so Close() skips it
			hasFailed = true
			continue
		}
		started++
	}
	if started == 0 {
		return fmt.Errorf("all %d node controllers failed to start", len(nodes))
	}
	log.Infof("%d/%d node controllers started successfully", started, len(nodes))

	// Start background retry for failed nodes
	if hasFailed {
		n.startRetryLoop()
	}
	return nil
}

// startRetryLoop periodically retries starting failed (nil) controllers.
// Port bind failures from TIME_WAIT typically resolve within 60 seconds.
func (n *Node) startRetryLoop() {
	n.stopRetry = make(chan struct{})
	go func() {
		retryInterval := 30 * time.Second
		maxRetries := 5
		for attempt := 1; attempt <= maxRetries; attempt++ {
			select {
			case <-time.After(retryInterval):
			case <-n.stopRetry:
				return
			}

			allStarted := true
			for i, c := range n.controllers {
				if c != nil {
					continue // already running
				}
				// Rebuild controller for this node
				node := n.nodeConfigs[i]
				p, err := panel.New(&node)
				if err != nil {
					log.WithFields(log.Fields{
						"host":    node.APIHost,
						"node_id": node.NodeID,
						"attempt": attempt,
						"err":     err,
					}).Warn("Retry: failed to create API client")
					allStarted = false
					continue
				}
				info, err := p.GetNodeInfo()
				if err != nil {
					log.WithFields(log.Fields{
						"host":    node.APIHost,
						"node_id": node.NodeID,
						"attempt": attempt,
						"err":     err,
					}).Warn("Retry: failed to get node info")
					allStarted = false
					continue
				}
				ctrl := NewController(p, &node, info)
				if err := ctrl.Start(n.v2core); err != nil {
					log.WithFields(log.Fields{
						"host":    node.APIHost,
						"node_id": node.NodeID,
						"attempt": attempt,
						"err":     err,
					}).Warn("Retry: failed to start node controller")
					allStarted = false
					continue
				}
				n.controllers[i] = ctrl
				n.NodeInfos[i] = info
				log.WithFields(log.Fields{
					"host":    node.APIHost,
					"node_id": node.NodeID,
					"attempt": attempt,
				}).Info("Retry: node controller started successfully")
			}

			if allStarted {
				log.Info("All failed nodes have been recovered")
				return
			}
		}
		log.Warn("Max retry attempts reached, some nodes may still be down")
	}()
}

func (n *Node) Close() error {
	// Stop retry loop if running
	if n.stopRetry != nil {
		select {
		case <-n.stopRetry:
			// already closed
		default:
			close(n.stopRetry)
		}
	}

	var err error
	for _, c := range n.controllers {
		if c == nil {
			continue // skipped node that failed to start
		}
		if err = c.Close(); err != nil {
			log.Errorf("close controller failed: %v", err)
			return err
		}
	}
	n.controllers = nil
	return nil
}
