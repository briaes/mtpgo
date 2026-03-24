package main

import (
	"sync"
	"sync/atomic"
	"time"
)

type Stats struct {
	mu sync.RWMutex

	ConnectsAll       int64
	ConnectsBad       int64
	HandshakeTimeouts int64

	ConnectsByDuration map[float64]int64

	SecretStats map[string]*SecretStat // key: hex secret
}

type SecretStat struct {
	Connects       int64
	CurrConnects   int64
	OctetsFromClt  int64
	OctetsToClt    int64
	MsgsFromClt    int64
	MsgsToClt      int64
}

var globalStats = &Stats{
	ConnectsByDuration: make(map[float64]int64),
	SecretStats:        make(map[string]*SecretStat),
}

var proxyStartTime = time.Now()

func (s *Stats) IncConnectsAll() { atomic.AddInt64(&s.ConnectsAll, 1) }
func (s *Stats) IncConnectsBad() { atomic.AddInt64(&s.ConnectsBad, 1) }
func (s *Stats) IncHandshakeTimeouts() { atomic.AddInt64(&s.HandshakeTimeouts, 1) }

func (s *Stats) UpdateDuration(d float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, bucket := range StatDurationBuckets {
		if d <= bucket {
			s.ConnectsByDuration[bucket]++
			return
		}
	}
}

func (s *Stats) GetOrCreateSecretStat(secretHex string) *SecretStat {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.SecretStats[secretHex]; ok {
		return st
	}
	st := &SecretStat{}
	s.SecretStats[secretHex] = st
	return st
}

func (ss *SecretStat) IncConnects()             { atomic.AddInt64(&ss.Connects, 1) }
func (ss *SecretStat) AddCurrConnects(n int64)  { atomic.AddInt64(&ss.CurrConnects, n) }
func (ss *SecretStat) AddOctetsFromClt(n int64) { atomic.AddInt64(&ss.OctetsFromClt, n) }
func (ss *SecretStat) AddOctetsToClt(n int64)   { atomic.AddInt64(&ss.OctetsToClt, n) }
func (ss *SecretStat) AddMsgsFromClt(n int64)   { atomic.AddInt64(&ss.MsgsFromClt, n) }
func (ss *SecretStat) AddMsgsToClt(n int64)     { atomic.AddInt64(&ss.MsgsToClt, n) }

func statsPrinter(cfg *Config) {
	for {
		time.Sleep(time.Duration(cfg.StatsPrintPeriod) * time.Second)
		logf("Stats for", time.Now().Format("02.01.2006 15:04:05" + "\n"))
		globalStats.mu.RLock()
		for secretHex, st := range globalStats.SecretStats {
			total := atomic.LoadInt64(&st.OctetsFromClt) + atomic.LoadInt64(&st.OctetsToClt)
			logf("%s: %d connects (%d current), %.2f MB, %d msgs\n",
				secretHex[:8]+"...",
				atomic.LoadInt64(&st.Connects),
				atomic.LoadInt64(&st.CurrConnects),
				float64(total)/1e6,
				atomic.LoadInt64(&st.MsgsFromClt)+atomic.LoadInt64(&st.MsgsToClt),
			)
		}
		globalStats.mu.RUnlock()
		logf("\n")
	}
}
