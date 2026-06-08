package dispatcher

import (
	"fmt"     // Added
	"sort"    // Added
	"strings" // Added
	sync "sync"
	"time"    // Added

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type ManagedWriter struct {
	writer  buf.Writer
	manager *LinkManager
}

func (w *ManagedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.writer.WriteMultiBuffer(mb)
}

func (w *ManagedWriter) Close() error {
	w.manager.RemoveWriter(w)
	return common.Close(w.writer)
}

// Added
type LinkInfo struct {
	Reader      buf.Reader
	Destination string
	StartTime   time.Time
}

// Modified
type LinkManager struct {
	links map[*ManagedWriter]LinkInfo
	mu    sync.RWMutex
}

// Modified
func (m *LinkManager) AddLink(writer *ManagedWriter, reader buf.Reader, dest string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.links[writer] = LinkInfo{
		Reader:      reader,
		Destination: dest,
		StartTime:   time.Now(),
	}
}

// Added
func (m *LinkManager) GetActiveCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.links)
}

// Added
func (m *LinkManager) GetActiveCountByPattern(pattern string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for _, info := range m.links {
		if strings.Contains(info.Destination, pattern) {
			count++
		}
	}
	return count
}

// Added
func (m *LinkManager) GetTopDomains(n int) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	domainMap := make(map[string]int)
	for _, info := range m.links {
		host := info.Destination
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			host = host[:idx]
		}
		domainMap[host]++
	}

	type domainCount struct {
		Domain string
		Count  int
	}
	var list []domainCount
	for k, v := range domainMap {
		list = append(list, domainCount{Domain: k, Count: v})
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].Count > list[j].Count
	})

	var result []string
	for i := 0; i < len(list) && i < n; i++ {
		result = append(result, fmt.Sprintf("%s:%d", list[i].Domain, list[i].Count))
	}
	return result
}

func (m *LinkManager) RemoveWriter(writer *ManagedWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.links, writer)
}

// Modified
func (m *LinkManager) CloseAll() {
	m.mu.Lock()
	// Copy the map to avoid lock re-entry in common.Close(w) -> w.Close() -> m.RemoveWriter(w)
	links := make(map[*ManagedWriter]buf.Reader, len(m.links))
	for w, info := range m.links {
		links[w] = info.Reader
	}
	// Clear the original map since all links will be closed
	m.links = make(map[*ManagedWriter]LinkInfo)
	m.mu.Unlock()

	for w, r := range links {
		common.Close(w)
		common.Interrupt(r)
	}
}
