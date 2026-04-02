package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"mtproxy/config"
	"mtproxy/crypto"
)

// proxySecretMu 保护 ProxySecret 的并发读写。
// ProxySecret 在 middleproxyHandshake（高频读）和 UpdateMiddleProxyInfo（低频写）
// 中并发访问，必须加锁。
var proxySecretMu sync.RWMutex

// GetProxySecret 线程安全地读取当前 ProxySecret。
func GetProxySecret() []byte {
	proxySecretMu.RLock()
	defer proxySecretMu.RUnlock()
	s := make([]byte, len(ProxySecret))
	copy(s, ProxySecret)
	return s
}

// setProxySecret 线程安全地更新 ProxySecret。
func setProxySecret(newSecret []byte) {
	proxySecretMu.Lock()
	defer proxySecretMu.Unlock()
	ProxySecret = newSecret
}

// ── 日志 ──────────────────────────────────────────────────────────────────────

var logWriter io.Writer

func SetLogger(w io.Writer) {
	logWriter = w
}

func Logf(format string, args ...interface{}) {
	if logWriter != nil {
		fmt.Fprintf(logWriter, format, args...)
	}
}

func Dbgf(cfg *config.Config, format string, args ...interface{}) {
	if cfg != nil && cfg.Debug {
		Logf(format, args...)
	}
}

// ── 中间代理列表更新 ──────────────────────────────────────────────────────────

func getNewProxies(url string) (map[int][][2]interface{}, error) {
	re := regexp.MustCompile(`proxy_for\s+(-?\d+)\s+(.+):(\d+)\s*;`)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	ans := make(map[int][][2]interface{})
	for _, match := range re.FindAllStringSubmatch(string(body), -1) {
		dcIdx, _ := strconv.Atoi(match[1])
		host := match[2]
		port, _ := strconv.Atoi(match[3])
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
		ans[dcIdx] = append(ans[dcIdx], [2]interface{}{host, port})
	}
	return ans, nil
}

// directDCURLs 提供直连 DC 地址的更新来源（Telegram 官方接口）
const (
	directDCAddrV4 = "https://core.telegram.org/getProxyConfig"
	directDCAddrV6 = "https://core.telegram.org/getProxyConfigV6"
)

// parseDCAddrs 从代理配置中提取 DC IP（格式同 proxy_for）
func parseDCAddrs(body string) []string {
	re := regexp.MustCompile(`proxy_for\s+\d+\s+(.+):\d+\s*;`)
	var ips []string
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		ip := m[1]
		if strings.HasPrefix(ip, "[") && strings.HasSuffix(ip, "]") {
			ip = ip[1 : len(ip)-1]
		}
		if !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	return ips
}

// UpdateDirectDCAddrs 从 Telegram 官方接口获取最新的直连 DC 地址并更新本地列表。
// 修复：直连模式的 DC 地址原先硬编码且从不更新；此函数在后台定期刷新。
func UpdateDirectDCAddrs() {
	client := &http.Client{Timeout: 10 * time.Second}
	for _, item := range []struct {
		url  string
		list *[]string
		mu   *sync.RWMutex
	}{
		{directDCAddrV4, &TGDatacentersV4, &TGDirectDCsMu},
		{directDCAddrV6, &TGDatacentersV6, &TGDirectDCsMu},
	} {
		resp, err := client.Get(item.url)
		if err != nil {
			Logf("Error fetching DC list from %s: %v\n", item.url, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		ips := parseDCAddrs(string(body))
		if len(ips) > 0 {
			item.mu.Lock()
			*item.list = ips
			item.mu.Unlock()
			Logf("Updated DC list from %s: %d addresses\n", item.url, len(ips))
		}
	}
}

func UpdateMiddleProxyInfo(cfg *config.Config) {
	const (
		proxyInfoAddr   = "https://core.telegram.org/getProxyConfig"
		proxyInfoAddrV6 = "https://core.telegram.org/getProxyConfigV6"
		proxySecretAddr = "https://core.telegram.org/getProxySecret"
	)

	for {
		// 更新 IPv4 代理列表
		v4, err := getNewProxies(proxyInfoAddr)
		if err != nil || len(v4) == 0 {
			Logf("Error updating middle proxy list: %v\n", err)
		} else {
			MiddleProxyMu.Lock()
			TGMiddleProxiesV4 = v4
			MiddleProxyMu.Unlock()
		}

		// 更新 IPv6 代理列表
		v6, err := getNewProxies(proxyInfoAddrV6)
		if err != nil || len(v6) == 0 {
			Logf("Error updating middle proxy list (IPv6): %v\n", err)
		} else {
			MiddleProxyMu.Lock()
			TGMiddleProxiesV6 = v6
			MiddleProxyMu.Unlock()
		}

		// 更新 ProxySecret（加锁写，防止与 middleproxyHandshake 并发读产生数据竞争）
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(proxySecretAddr)
		if err != nil {
			Logf("Error updating middle proxy secret: %v\n", err)
		} else {
			secret, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if len(secret) > 0 {
				newSecret := make([]byte, len(secret))
				copy(newSecret, secret)
				current := GetProxySecret()
				if string(newSecret) != string(current) {
					setProxySecret(newSecret)
					Logf("Middle proxy secret updated\n")
				}
			}
		}

		// 同步刷新直连 DC 地址（两者使用相同的更新周期）
		UpdateDirectDCAddrs()

		time.Sleep(time.Duration(cfg.ProxyInfoUpdatePeriod) * time.Second)
	}
}

// ── TLS 证书长度获取 ──────────────────────────────────────────────────────────

var FakeCertLen = 2048 // 默认值
var FakeCertMu sync.RWMutex

func GetMaskHostCertLen(cfg *config.Config) {
	const getCertTimeout = 10 * time.Second
	const maskEnablingCheckPeriod = 60 * time.Second

	for {
		if !cfg.Mask {
			time.Sleep(maskEnablingCheckPeriod)
			continue
		}

		func() {
			conn, err := tls.DialWithDialer(
				&net.Dialer{Timeout: getCertTimeout},
				"tcp",
				fmt.Sprintf("%s:%d", cfg.MaskHost, cfg.MaskPort),
				&tls.Config{
					ServerName:         cfg.TLSDomain,
					InsecureSkipVerify: true,
				},
			)
			if err != nil {
				Logf("Failed to connect to MASK_HOST %s: %v\n", cfg.MaskHost, err)
				return
			}
			defer conn.Close()

			// 获取证书原始数据长度
			state := conn.ConnectionState()
			if len(state.PeerCertificates) == 0 {
				Logf("MASK_HOST %s returned no certificates\n", cfg.MaskHost)
				return
			}
			certLen := len(state.PeerCertificates[0].Raw)
			if certLen < MinCertLen {
				Logf("MASK_HOST %s cert too short: %d\n", cfg.MaskHost, certLen)
				return
			}

			FakeCertMu.Lock()
			if certLen != FakeCertLen {
				FakeCertLen = certLen
				Logf("Got cert from MASK_HOST %s, length: %d\n", cfg.MaskHost, certLen)
			}
			FakeCertMu.Unlock()
		}()

		time.Sleep(time.Duration(cfg.GetCertLenPeriod) * time.Second)
	}
}

// ── IP 缓存清理 ───────────────────────────────────────────────────────────────

// ClearIPResolvingCache 定期主动解析 MaskHost 的 IP，使 Go 运行时的 DNS 缓存
// 得到刷新。Go 标准库的 DNS 缓存 TTL 约 5 秒（正缓存）/ 2 秒（负缓存），
// 在长期运行的场景下，主动解析确保 MaskHost IP 变更能及时生效。
func ClearIPResolvingCache() {
	for {
		sleepTime := 60 + crypto.GlobalRand.Intn(60)
		time.Sleep(time.Duration(sleepTime) * time.Second)

		// 主动解析一次，触发 Go DNS 缓存刷新
		if maskHost := currentMaskHost(); maskHost != "" {
			if _, err := net.LookupHost(maskHost); err != nil {
				Logf("DNS lookup failed for mask host %s: %v\n", maskHost, err)
			}
		}
	}
}

// currentMaskHost 通过包级变量缓存读取当前 MaskHost，
// 由 SetMaskHost 在启动时设置，避免循环依赖 config 包。
var maskHostVal string
var maskHostMu sync.RWMutex

func SetMaskHost(host string) {
	maskHostMu.Lock()
	defer maskHostMu.Unlock()
	maskHostVal = host
}

func currentMaskHost() string {
	maskHostMu.RLock()
	defer maskHostMu.RUnlock()
	return maskHostVal
}
