package stats

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"mtproxy/config"
)

// ── Prometheus metrics 格式输出 ───────────────────────────────────────────────

type metricEntry struct {
	name   string
	mtype  string
	desc   string
	labels map[string]string
	val    interface{}
}

func makeMetricsPkt(entries []metricEntry, prefix string) string {
	var sb strings.Builder
	usedNames := map[string]bool{}

	for _, e := range entries {
		fullName := prefix + e.name
		if !usedNames[fullName] {
			fmt.Fprintf(&sb, "# HELP %s %s\n", fullName, e.desc)
			fmt.Fprintf(&sb, "# TYPE %s %s\n", fullName, e.mtype)
			usedNames[fullName] = true
		}

		if len(e.labels) > 0 {
			var tags []string
			valStr := fmt.Sprintf("%v", e.val)
			for k, v := range e.labels {
				if k == "val" {
					valStr = v
					continue
				}
				escaped := strings.ReplaceAll(v, `"`, `\"`)
				tags = append(tags, fmt.Sprintf(`%s="%s"`, k, escaped))
			}
			fmt.Fprintf(&sb, "%s{%s} %s\n", fullName, strings.Join(tags, ","), valStr)
		} else {
			fmt.Fprintf(&sb, "%s %v\n", fullName, e.val)
		}
	}
	return sb.String()
}

// ── metrics handler ───────────────────────────────────────────────────────────

func MetricsHandler(cfg *config.Config, proxyLinks []map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr
		if host, _, err := net.SplitHostPort(clientIP); err == nil {
			clientIP = host
		}

		// 白名单检查
		allowed := false
		for _, ip := range cfg.MetricsWhitelist {
			if ip == clientIP {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		var entries []metricEntry

		uptime := time.Since(ProxyStartTime).Seconds()
		entries = append(entries, metricEntry{"uptime", "counter", "proxy uptime", nil, uptime})
		entries = append(entries, metricEntry{"connects_bad", "counter", "connects with bad secret", nil,
			atomic.LoadInt64(&GlobalStats.ConnectsBad)})
		entries = append(entries, metricEntry{"connects_all", "counter", "incoming connects", nil,
			atomic.LoadInt64(&GlobalStats.ConnectsAll)})
		entries = append(entries, metricEntry{"handshake_timeouts", "counter", "number of timed out handshakes", nil,
			atomic.LoadInt64(&GlobalStats.HandshakeTimeouts)})

		// 代理链接信息
		if cfg.MetricsExportLinks {
			for _, link := range proxyLinks {
				labels := map[string]string{
					"link": link["link"],
					"val":  "1",
				}
				entries = append(entries, metricEntry{"proxy_link_info", "counter", "the proxy link info", labels, 1})
			}
		}

		// 连接时长桶
		GlobalStats.Mu.RLock()
		bucketStart := 0.0
		for _, bucket := range DurationBuckets {
			bucketEnd := fmt.Sprintf("%v", bucket)
			if bucket == DurationBuckets[len(DurationBuckets)-1] {
				bucketEnd = "+Inf"
			}
			labels := map[string]string{
				"bucket": fmt.Sprintf("%v-%s", bucketStart, bucketEnd),
				"val":    fmt.Sprintf("%d", GlobalStats.ConnectsByDuration[bucket]),
			}
			entries = append(entries, metricEntry{"connects_by_duration", "counter", "connects by duration", labels, GlobalStats.ConnectsByDuration[bucket]})
			bucketStart = bucket
		}
		GlobalStats.Mu.RUnlock()

		// 每个 secret 的统计
		type userMetric struct {
			name    string
			mtype   string
			desc    string
			statKey string
		}
		userMetrics := []userMetric{
			{"user_connects", "counter", "user connects", "connects"},
			{"user_connects_curr", "gauge", "current user connects", "curr_connects"},
			{"user_octets", "counter", "octets proxied for user", "octets_total"},
			{"user_msgs", "counter", "msgs proxied for user", "msgs_total"},
			{"user_octets_from", "counter", "octets from user", "octets_from_client"},
			{"user_octets_to", "counter", "octets to user", "octets_to_client"},
			{"user_msgs_from", "counter", "msgs from user", "msgs_from_client"},
			{"user_msgs_to", "counter", "msgs to user", "msgs_to_client"},
		}

		GlobalStats.Mu.RLock()
		for secretHex, st := range GlobalStats.SecretStats {
			for _, um := range userMetrics {
				var val int64
				switch um.statKey {
				case "connects":
					val = atomic.LoadInt64(&st.Connects)
				case "curr_connects":
					val = atomic.LoadInt64(&st.CurrConnects)
				case "octets_total":
					val = atomic.LoadInt64(&st.OctetsFromClt) + atomic.LoadInt64(&st.OctetsToClt)
				case "msgs_total":
					val = atomic.LoadInt64(&st.MsgsFromClt) + atomic.LoadInt64(&st.MsgsToClt)
				case "octets_from_client":
					val = atomic.LoadInt64(&st.OctetsFromClt)
				case "octets_to_client":
					val = atomic.LoadInt64(&st.OctetsToClt)
				case "msgs_from_client":
					val = atomic.LoadInt64(&st.MsgsFromClt)
				case "msgs_to_client":
					val = atomic.LoadInt64(&st.MsgsToClt)
				}
				labels := map[string]string{
					"user": secretHex[:8] + "...",
					"val":  fmt.Sprintf("%d", val),
				}
				entries = append(entries, metricEntry{um.name, um.mtype, um.desc, labels, val})
			}
		}
		GlobalStats.Mu.RUnlock()

		body := makeMetricsPkt(entries, cfg.MetricsPrefix)

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, body)
	}
}

func StartMetricsServer(cfg *config.Config, proxyLinks []map[string]string) {
	if cfg.MetricsPort == 0 {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", MetricsHandler(cfg, proxyLinks))

	if cfg.MetricsListenAddrV4 != "" {
		addr := fmt.Sprintf("%s:%d", cfg.MetricsListenAddrV4, cfg.MetricsPort)
		go func() {
			srv := &http.Server{Addr: addr, Handler: mux}
			if err := srv.ListenAndServe(); err != nil {
				fmt.Printf("Metrics server error: %v\n", err)
			}
		}()
	}

	if cfg.MetricsListenAddrV6 != "" {
		addr := fmt.Sprintf("[%s]:%d", cfg.MetricsListenAddrV6, cfg.MetricsPort)
		go func() {
			srv := &http.Server{Addr: addr, Handler: mux}
			if err := srv.ListenAndServe(); err != nil {
				fmt.Printf("Metrics server (v6) error: %v\n", err)
			}
		}()
	}
}
