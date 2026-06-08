package cmd

import (
	"context" // Added
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug" // Added
	"strings"       // Added
	"sync"          // Added
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/xxntmctx/v2node/common/task"
	"github.com/xxntmctx/v2node/conf"
	"github.com/xxntmctx/v2node/core"
	"github.com/xxntmctx/v2node/limiter"
	"github.com/xxntmctx/v2node/node"
)

var (
	config string
	watch  bool
)

var serverCommand = cobra.Command{
	Use:   "server",
	Short: "Run v2node server",
	Run:   serverHandle,
	Args:  cobra.NoArgs,
}

func init() {
	serverCommand.PersistentFlags().
		StringVarP(&config, "config", "c",
			"/etc/v2node/config.json", "config file path")
	serverCommand.PersistentFlags().
		BoolVarP(&watch, "watch", "w",
			true, "watch file path change")
	command.AddCommand(&serverCommand)
}

func serverHandle(_ *cobra.Command, _ []string) {
	showVersion()
	c := conf.New()
	err := c.LoadFromPath(config)
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: true,
		DisableQuote:     true,
		PadLevelText:     false,
	})
	if err != nil {
		log.WithField("err", err).Error("Load config file failed")
		return
	}
	// Apply Go runtime optimizations
	// Added
	if c.GOGC > 0 {
		debug.SetGCPercent(c.GOGC)
	}
	if c.MemLimit > 0 {
		debug.SetMemoryLimit(c.MemLimit)
	}
	switch c.LogConfig.Level {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn", "warning":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	}
	if c.LogConfig.Output != "" {
		f, err := os.OpenFile(c.LogConfig.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.WithField("err", err).Error("Open log file failed, using stdout instead")
		}
		log.SetOutput(f)
		task.DumpDir = filepath.Dir(c.LogConfig.Output) // Added
	}
	// Enable pprof if configured
	if c.PprofPort != 0 {
		go func() {
			log.Infof("Starting pprof server on :%d", c.PprofPort)
			if err := http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", c.PprofPort), nil); err != nil {
				log.WithField("err", err).Error("pprof server failed")
			}
		}()
	}
	//init limiter
	limiter.Init()
	//get node info
	nodes, err := node.New(c.NodeConfigs)
	if err != nil {
		log.WithField("err", err).Error("Get node info failed")
		return
	}
	log.Info("Got nodes info from server")
	//core
	var reloadCh = make(chan struct{}, 1)
	v2core := core.New(c)
	v2core.ReloadCh = reloadCh
	err = v2core.Start(nodes.NodeInfos)
	if err != nil {
		log.WithField("err", err).Error("Start core failed")
		return
	}
	defer v2core.Close()
	//node
	err = nodes.Start(c.NodeConfigs, v2core)
	if err != nil {
		log.WithField("err", err).Error("Run nodes failed")
		return
	}
	log.Info("Nodes started")

	// Monitor lifecycle management
	// Added
	var monitorCancel context.CancelFunc
	if c.Monitor.Enable {
		var ctx context.Context
		ctx, monitorCancel = context.WithCancel(context.Background())
		go startMonitor(ctx, c, v2core)
	}

	if watch {
		// On file change, just signal reload; do not run reload concurrently here
		err = c.Watch(config, func() {
			select {
			case reloadCh <- struct{}{}:
			default: // drop if a reload is already queued
			}
		})
		if err != nil {
			log.WithField("err", err).Error("start watch failed")
			// Added: clean up monitor before exit
			if monitorCancel != nil {
				monitorCancel()
			}
			return
		}
	}
	// clear memory
	runtime.GC()

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-osSignals:
			log.Info("收到退出信号，正在关闭程序...")
			// Added: clean up monitor before exit
			if monitorCancel != nil {
				monitorCancel()
			}
			os.Exit(0)
		case <-reloadCh:
			log.Info("收到重启信号，正在重新加载配置...")
			// Added: cancel old monitor
			if monitorCancel != nil {
				monitorCancel()
				monitorCancel = nil
			}
			if err := reload(config, &nodes, &v2core); err != nil {
				log.WithField("err", err).Error("重启失败，30秒后重试...")
				// Wait before retrying to allow ports to release
				time.Sleep(30 * time.Second)
				// Re-queue reload signal for retry
				select {
				case reloadCh <- struct{}{}:
				default:
				}
				continue
			}
			log.Info("重启成功")
			// Added: start new monitor
			if v2core.Config.Monitor.Enable {
				var ctx context.Context
				ctx, monitorCancel = context.WithCancel(context.Background())
				go startMonitor(ctx, v2core.Config, v2core)
			}
		}
	}
}

func reload(config string, nodes **node.Node, v2core **core.V2Core) error {
	// Preserve old reload channel so new core continues to receive signals
	var oldReloadCh chan struct{}
	if *v2core != nil {
		oldReloadCh = (*v2core).ReloadCh
	}

	if err := (*nodes).Close(); err != nil {
		return err
	}

	if err := (*v2core).Close(); err != nil {
		return err
	}

	// Wait for old listeners to fully release (TCP TIME_WAIT)
	// Without this, the new core may fail with "bind: address already in use"
	log.Info("等待端口释放...")
	time.Sleep(3 * time.Second)

	newConf := conf.New()
	if err := newConf.LoadFromPath(config); err != nil {
		return err
	}

	// Apply Go runtime optimizations
	// Added
	if newConf.GOGC > 0 {
		debug.SetGCPercent(newConf.GOGC)
	}
	if newConf.MemLimit > 0 {
		debug.SetMemoryLimit(newConf.MemLimit)
	}

	switch newConf.LogConfig.Level {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn", "warning":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	}
	if newConf.LogConfig.Output != "" {
		f, err := os.OpenFile(newConf.LogConfig.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.WithField("err", err).Error("Open log file failed, using stdout instead")
		} else {
			// 关闭旧 of 日志文件（如果是文件）
			if oldWriter, ok := log.StandardLogger().Out.(*os.File); ok && oldWriter != os.Stdout && oldWriter != os.Stderr {
				oldWriter.Close()
			}
			log.SetOutput(f)
			task.DumpDir = filepath.Dir(newConf.LogConfig.Output) // Added
		}
	}

	newNodes, err := node.New(newConf.NodeConfigs)
	if err != nil {
		return err
	}

	newCore := core.New(newConf)
	// Reattach reload channel
	newCore.ReloadCh = oldReloadCh
	if err := newCore.Start(newNodes.NodeInfos); err != nil {
		newCore.Close()
		return err
	}

	if err := newNodes.Start(newConf.NodeConfigs, newCore); err != nil {
		newNodes.Close()
		newCore.Close()
		return err
	}

	*nodes = newNodes
	*v2core = newCore

	runtime.GC()
	return nil
}

// Added: 线程安全地记录每个用户触发报警的次数
var triggerCounter = struct {
	sync.RWMutex
	counts map[string]int
}{
	counts: make(map[string]int),
}

// startMonitor runs a background goroutine to log top active users and warn on memory/connection spikes.
// Modified
func startMonitor(ctx context.Context, c *conf.Conf, v2core *core.V2Core) {
	log.Infof("活跃连接监控已启动，检测间隔：%d秒，报警阈值：%d", c.Monitor.Interval, c.Monitor.LogThreshold)
	ticker := time.NewTicker(time.Duration(c.Monitor.Interval) * time.Second)
	defer ticker.Stop()

	lastReportTime := time.Now().Add(-5 * time.Minute) // 启动后尽快做第一次常规报告
	for {
		select {
		case <-ctx.Done():
			log.Info("监控收到取消信号，Monitor 协程退出")
			return
		case <-ticker.C:
			// 堆内存状态
			var memStats runtime.MemStats
			runtime.ReadMemStats(&memStats)

			// 检查是否发生内存警戒
			var isMemoryWarn bool
			if c.MemLimit > 0 && memStats.Alloc > uint64(float64(c.MemLimit)*0.85) {
				isMemoryWarn = true
			}

			// 获取活跃连接排行 (TOP 5)
			topUsers := v2core.GetTopActiveUsers(5)

			// 检查是否有用户连接数超过警报线
			var hasUserLimitWarn bool
			var warnUsers []string
			nowStr := time.Now().Format("2006-01-02 15:04:05")
			for _, userStr := range topUsers {
				if idx := strings.Index(userStr, "(conns:"); idx != -1 {
					var conns int
					_, err := fmt.Sscanf(userStr[idx:], "(conns:%d)", &conns)
					if err == nil && conns >= c.Monitor.LogThreshold {
						hasUserLimitWarn = true
						email := userStr[:idx]

						// 触发计数自增
						triggerCounter.Lock()
						triggerCounter.counts[email]++
						times := triggerCounter.counts[email]
						triggerCounter.Unlock()

						// 获取该用户活跃域名的前 5 名
						topDomains := v2core.GetTopDomainsForUser(email, 5)

						// 组合审计详细信息
						warnDetail := fmt.Sprintf("[%s] %s(当前连接:%d, 累计报警:%d次, 活跃域名TOP5:%v)", nowStr, email, conns, times, topDomains)
						warnUsers = append(warnUsers, warnDetail)
					}
				}
			}

			// 触发警告日志
			if isMemoryWarn {
				log.Warnf("[WARN] 内存占用已达警戒线！当前已分配堆内存：%d MB, 限制：%d MB. 活跃用户 TOP 5: %v", memStats.Alloc/1024/1024, c.MemLimit/1024/1024, topUsers)
			}
			if hasUserLimitWarn {
				log.Warnf("[WARN] 检测到异常并发连接用户！触发阈值连接数 (%d): %v", c.Monitor.LogThreshold, warnUsers)
			}

			// 常规报告 (每 5 分钟打印一次)
			if time.Since(lastReportTime) >= 5*time.Minute {
				log.Infof("[INFO] 活跃用户排行 TOP 5: %v | 当前堆内存分配：%d MB", topUsers, memStats.Alloc/1024/1024)
				lastReportTime = time.Now()
			}
		}
	}
}
