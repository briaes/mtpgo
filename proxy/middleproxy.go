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

// ── 日志系统 ─────────────────────────────────────────────────────────────────
//
// 四个级别从低到高：debug < info < warn < error
// 配置文件通过 LOG_LEVEL 字段控制最低输出级别。
// 低于当前级别的日志调用直接返回，零开销（无格式化）。

const (
	LevelDebug = iota
	LevelInfo
	LevelWarn
	LevelError
)

var logWriter io.Writer
var logLevel = LevelInfo // 默认 info，由 SetLogLevel 更新

func SetLogger(w io.Writer) {
	logWriter = w
}

// SetLogLevel 将字符串级别转换为内部整数并存储。
func SetLogLevel(level string) {
	switch level {
	case "debug":
		logLevel = LevelDebug
	case "info":
		logLevel = LevelInfo
	case "warn":
		logLevel = LevelWarn
	case "error":
		logLevel = LevelError
	default:
		logLevel = LevelInfo
	}
}

func logWrite(format string, args ...interface{}) {
	if logWriter != nil {
		fmt.Fprintf(logWriter, format, args...)
	}
}

// Debugf 输出 debug 级别日志，需传入 cfg 以读取当前日志级别。
// 设计为接受 cfg 而非全局变量，方便热重载后立即生效。
func Debugf(cfg *config.Config, format string, args ...interface{}) {
	if cfg != nil && logLevel <= LevelDebug {
		logWrite("[DEBUG] "+format, args...)
	}
}

// Infof 输出 info 级别日志。
func Infof(format string, args ...interface{}) {
	if logLevel <= LevelInfo {
		logWrite("[INFO]  "+format, args...)
	}
}

// Warnf 输出 warn 级别日志。
func Warnf(format string, args ...interface{}) {
	if logLevel <= LevelWarn {
		logWrite("[WARN]  "+format, args...)
	}
}

// Errorf 输出 error 级别日志。
func Errorf(format string, args ...interface{}) {
	if logLevel <= LevelError {
		logWrite("[ERROR] "+format, args...)
	}
}

// Logf 保留作为兼容别名，等同于 Infof。
// 仅供 stats.StatsPrinter 等传函数指针的场景使用。
func Logf(format string, args ...interface{}) {
	Infof(format, args...)
}

// Dbgf 保留作为兼容别名，等同于 Debugf。
func Dbgf(cfg *config.Config, format string, args ...interface{}) {
	Debugf(cfg, format, args...)
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
			Errorf("Error updating middle proxy list: %v\n", err)
		} else {
			MiddleProxyMu.Lock()
			TGMiddleProxiesV4 = v4
			MiddleProxyMu.Unlock()
		}

		// 更新 IPv6 代理列表
		v6, err := getNewProxies(proxyInfoAddrV6)
		if err != nil || len(v6) == 0 {
			Errorf("Error updating middle proxy list (IPv6): %v\n", err)
		} else {
			MiddleProxyMu.Lock()
			TGMiddleProxiesV6 = v6
			MiddleProxyMu.Unlock()
		}

		// 更新 ProxySecret（加锁写，防止与 middleproxyHandshake 并发读产生数据竞争）
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(proxySecretAddr)
		if err != nil {
			Errorf("Error updating middle proxy secret: %v\n", err)
		} else {
			secret, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if len(secret) > 0 {
				newSecret := make([]byte, len(secret))
				copy(newSecret, secret)
				current := GetProxySecret()
				if string(newSecret) != string(current) {
					setProxySecret(newSecret)
					Infof("Middle proxy secret updated\n")
				}
			}
		}

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
				Warnf("Failed to connect to MASK_HOST %s: %v\n", cfg.MaskHost, err)
				return
			}
			defer conn.Close()

			// 获取证书原始数据长度
			state := conn.ConnectionState()
			if len(state.PeerCertificates) == 0 {
				Warnf("MASK_HOST %s returned no certificates\n", cfg.MaskHost)
				return
			}
			certLen := len(state.PeerCertificates[0].Raw)
			if certLen < MinCertLen {
				Warnf("MASK_HOST %s cert too short: %d\n", cfg.MaskHost, certLen)
				return
			}

			FakeCertMu.Lock()
			if certLen != FakeCertLen {
				FakeCertLen = certLen
				Infof("Got cert from MASK_HOST %s, length: %d\n", cfg.MaskHost, certLen)
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
				Warnf("DNS lookup failed for mask host %s: %v\n", maskHost, err)
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
