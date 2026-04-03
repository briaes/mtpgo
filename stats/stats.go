package stats

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"mtproxy/config"
)

// ── 统计数据 ──────────────────────────────────────────────────────────────────

type Stats struct {
	// ConnectsAll/Bad/HandshakeTimeouts 用 atomic 保护，热路径无锁更新
	ConnectsAll       int64
	ConnectsBad       int64
	HandshakeTimeouts int64

	// ConnectsByDuration 和 SecretStats 用 Mu 保护（写频率低）
	Mu                 sync.RWMutex
	ConnectsByDuration map[float64]int64
	SecretStats        map[string]*SecretStat // key: hex secret
}

// SecretStat 每个 secret 的独立统计，全部字段用 atomic 保护，
// 允许在持有 Stats.Mu.RLock 时无锁更新各字段，避免全局锁竞争。
type SecretStat struct {
	Connects      int64
	CurrConnects  int64
	OctetsFromClt int64
	OctetsToClt   int64
	MsgsFromClt   int64
	MsgsToClt     int64
}

var GlobalStats = &Stats{
	ConnectsByDuration: make(map[float64]int64),
	SecretStats:        make(map[string]*SecretStat),
}

var ProxyStartTime = time.Now()

var DurationBuckets = []float64{0.1, 0.5, 1, 2, 5, 15, 60, 300, 600, 1800, 1e9}

func (s *Stats) IncConnectsAll()       { atomic.AddInt64(&s.ConnectsAll, 1) }
func (s *Stats) IncConnectsBad()       { atomic.AddInt64(&s.ConnectsBad, 1) }
func (s *Stats) IncHandshakeTimeouts() { atomic.AddInt64(&s.HandshakeTimeouts, 1) }

func (s *Stats) UpdateDuration(d float64) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	for _, bucket := range DurationBuckets {
		if d <= bucket {
			s.ConnectsByDuration[bucket]++
			return
		}
	}
}

// GetOrCreateSecretStat 线程安全地获取或创建 secret 统计项。
// 先用读锁快速路径查找，未命中再升级为写锁创建，减少写锁持有时间。
func (s *Stats) GetOrCreateSecretStat(secretHex string) *SecretStat {
	s.Mu.RLock()
	st, ok := s.SecretStats[secretHex]
	s.Mu.RUnlock()
	if ok {
		return st
	}
	s.Mu.Lock()
	defer s.Mu.Unlock()
	// 双重检查，防止并发创建
	if st, ok = s.SecretStats[secretHex]; ok {
		return st
	}
	st = &SecretStat{}
	s.SecretStats[secretHex] = st
	return st
}

func (ss *SecretStat) IncConnects()             { atomic.AddInt64(&ss.Connects, 1) }
func (ss *SecretStat) AddCurrConnects(n int64)  { atomic.AddInt64(&ss.CurrConnects, n) }
func (ss *SecretStat) AddOctetsFromClt(n int64) { atomic.AddInt64(&ss.OctetsFromClt, n) }
func (ss *SecretStat) AddOctetsToClt(n int64)   { atomic.AddInt64(&ss.OctetsToClt, n) }
func (ss *SecretStat) AddMsgsFromClt(n int64)   { atomic.AddInt64(&ss.MsgsFromClt, n) }
func (ss *SecretStat) AddMsgsToClt(n int64)     { atomic.AddInt64(&ss.MsgsToClt, n) }

// StatsPrinter 定期打印统计摘要。
// 修复：
//   - 删除无意义的 fmt.Fprintf(io.Discard, "") hack
//   - 读 SecretStats map 用 RLock，读各字段用 atomic.Load，并发保护一致
func StatsPrinter(cfg *config.Config, logf func(string, ...interface{})) {
	for {
		time.Sleep(time.Duration(cfg.StatsPrintPeriod) * time.Second)
		logf("Stats for %s\n", time.Now().Format("02.01.2006 15:04:05"))

		// 快照 SecretStats：持 RLock 期间只读 map，字段读取用 atomic
		GlobalStats.Mu.RLock()
		for secretHex, st := range GlobalStats.SecretStats {
			total := atomic.LoadInt64(&st.OctetsFromClt) + atomic.LoadInt64(&st.OctetsToClt)
			logf("%s: %d connects (%d current), %.2f MB, %d msgs\n",
				secretHex[:8]+"...",
				atomic.LoadInt64(&st.Connects),
				atomic.LoadInt64(&st.CurrConnects),
				float64(total)/1e6,
				atomic.LoadInt64(&st.MsgsFromClt)+atomic.LoadInt64(&st.MsgsToClt),
			)
		}
		GlobalStats.Mu.RUnlock()

		logf("\n")
	}
}

// StatsPrinterAtomic 是 StatsPrinter 的 AtomicConfig 版本。
// 每次循环迭代时通过 atomicCfg.Get() 取得最新配置，热重载后自动使用新的 StatsPrintPeriod。
func StatsPrinterAtomic(atomicCfg *config.AtomicConfig, logf func(string, ...interface{})) {
	for {
		cfg := atomicCfg.Get()
		time.Sleep(time.Duration(cfg.StatsPrintPeriod) * time.Second)
		logf("Stats for %s\n", time.Now().Format("02.01.2006 15:04:05"))

		GlobalStats.Mu.RLock()
		for secretHex, st := range GlobalStats.SecretStats {
			total := atomic.LoadInt64(&st.OctetsFromClt) + atomic.LoadInt64(&st.OctetsToClt)
			logf("%s: %d connects (%d current), %.2f MB, %d msgs\n",
				secretHex[:8]+"...",
				atomic.LoadInt64(&st.Connects),
				atomic.LoadInt64(&st.CurrConnects),
				float64(total)/1e6,
				atomic.LoadInt64(&st.MsgsFromClt)+atomic.LoadInt64(&st.MsgsToClt),
			)
		}
		GlobalStats.Mu.RUnlock()

		logf("\n")
	}
}

// FormatStats 返回当前统计的文本摘要，供 metrics 和日志共用。
func FormatStats() string {
	all := atomic.LoadInt64(&GlobalStats.ConnectsAll)
	bad := atomic.LoadInt64(&GlobalStats.ConnectsBad)
	timeouts := atomic.LoadInt64(&GlobalStats.HandshakeTimeouts)
	return fmt.Sprintf("all=%d bad=%d timeouts=%d", all, bad, timeouts)
}
