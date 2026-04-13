package node

import (
	"math/rand/v2"
	"time"

	log "github.com/sirupsen/logrus"
	panel "github.com/xxntmctx/v2node/api/v2board"
	"github.com/xxntmctx/v2node/common/task"
	vCore "github.com/xxntmctx/v2node/core"
)

func (c *Controller) startTasks(node *panel.NodeInfo) {
	// Add random jitter (0-10s) to prevent all nodes from hitting the
	// panel API simultaneously, which causes request storms and timeouts.
	jitter := time.Duration(rand.IntN(10000)) * time.Millisecond

	// fetch node info task
	c.nodeInfoMonitorPeriodic = &task.Task{
		Name:     "nodeInfoMonitor",
		Interval: node.PullInterval + jitter,
		Execute:  c.nodeInfoMonitor,
		Reload:   c.reloadTask,
	}
	// fetch user list task
	c.userReportPeriodic = &task.Task{
		Name:     "reportUserTrafficTask",
		Interval: node.PushInterval + jitter,
		Execute:  c.reportUserTrafficTask,
		Reload:   c.reloadTask,
	}
	log.WithField("tag", c.tag).Infof("Start monitor node status (jitter: %v)", jitter)
	// delay to start nodeInfoMonitor
	_ = c.nodeInfoMonitorPeriodic.Start(false)
	log.WithField("tag", c.tag).Info("Start report node status")
	_ = c.userReportPeriodic.Start(false)
	if node.Security == panel.Tls {
		switch c.info.Common.CertInfo.CertMode {
		case "none", "", "file", "self":
		default:
			c.renewCertPeriodic = &task.Task{
				Name:     "renewCertTask",
				Interval: time.Hour * 24,
				Execute:  c.renewCertTask,
				Reload:   c.reloadTask,
			}
			log.WithField("tag", c.tag).Info("Start renew cert")
			// delay to start renewCert
			_ = c.renewCertPeriodic.Start(true)
		}
	}
}

func (c *Controller) reloadTask() {
	// Debounce: prevent concurrent reloads from multiple timed-out goroutines
	c.reloadMu.Lock()
	if c.reloading {
		c.reloadMu.Unlock()
		log.WithField("tag", c.tag).Warn("Reload already in progress, skipping")
		return
	}
	c.reloading = true
	c.reloadMu.Unlock()
	defer func() {
		c.reloadMu.Lock()
		c.reloading = false
		c.reloadMu.Unlock()
	}()

	newClient, err := panel.New(c.conf)
	if err != nil {
		log.WithField("tag", c.tag).Error("Tasks reload failed: cannot create new API client")
		return
	}
	c.apiClient = newClient
	c.nodeInfoMonitorPeriodic.Close()
	c.userReportPeriodic.Close()
	if c.renewCertPeriodic != nil {
		c.renewCertPeriodic.Close()
	}
	c.startTasks(c.info)
}

func (c *Controller) nodeInfoMonitor() (err error) {
	// get node info
	newN, err := c.apiClient.GetNodeInfo()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Get node info failed")
		return nil
	}
	if newN != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
		}).Info("Got new node info, triggering reload")
		// Non-blocking signal to avoid goroutine stuck when channel is full or nil
		if c.server.ReloadCh != nil {
			select {
			case c.server.ReloadCh <- struct{}{}:
			default:
				log.WithField("tag", c.tag).Warn("Reload already queued, skipping")
			}
		} else {
			log.WithField("tag", c.tag).Error("ReloadCh is nil, cannot trigger reload")
		}
		// Return immediately — do NOT continue to DelUsers/AddUsers
		// because reload will destroy and rebuild the core instance.
		// Continuing here would race with Close() and cause
		// "inbound manager is nil" errors.
		return nil
	}
	log.WithField("tag", c.tag).Debug("Node info no change")

	// get user info
	newU, err := c.apiClient.GetUserList()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Get user list failed")
		return nil
	}
	// get user alive
	newA, err := c.apiClient.GetUserAlive()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Get alive list failed")
		return nil
	}

	// update alive list
	if newA != nil {
		c.limiter.AliveList = newA
	}
	// node no changed, check users
	if len(newU) == 0 {
		log.WithField("tag", c.tag).Debug("User list no change")
		return nil
	}
	deleted, added, modified := compareUserList(c.userList, newU)
	if len(deleted) > 0 {
		// have deleted users
		err = c.server.DelUsers(deleted, c.tag, c.info)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Delete users failed")
			return nil
		}
	}
	if len(added) > 0 {
		// have added users
		_, err = c.server.AddUsers(&vCore.AddUsersParams{
			Tag:      c.tag,
			NodeInfo: c.info,
			Users:    added,
		})
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Add users failed")
			return nil
		}
	}
	if len(added) > 0 || len(deleted) > 0 || len(modified) > 0 {
		// update Limiter
		c.limiter.UpdateUser(c.tag, added, deleted, modified)
	}
	c.userList = newU
	log.WithField("tag", c.tag).Infof("%d user deleted, %d user added, %d user modified", len(deleted), len(added), len(modified))
	return nil
}
