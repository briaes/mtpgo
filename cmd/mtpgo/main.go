package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"mtproxy/config"
	"mtproxy/crypto"
	"mtproxy/proxy"
	"mtproxy/stats"
)

// ── 日志 ──────────────────────────────────────────────────────────────────────

var logWriter io.Writer = os.Stderr
var logFile *os.File

func setupLogger() {
	logDir := filepath.Dir(os.Args[0])
	logPath := filepath.Join(logDir, "log_mtpgo")
	var err error
	logFile, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法创建日志文件 %s: %v\n", logPath, err)
		return
	}
	logWriter = io.MultiWriter(os.Stderr, logFile)
}

func logf(format string, args ...interface{}) {
	fmt.Fprintf(logWriter, format, args...)
}

// main 包专用的分级日志辅助，直接写入 logWriter，与 proxy 包共享同一 writer
func infof(format string, args ...interface{})  { fmt.Fprintf(logWriter, "[INFO]  "+format, args...) }
func warnf(format string, args ...interface{})  { fmt.Fprintf(logWriter, "[WARN]  "+format, args...) }
func errorf(format string, args ...interface{}) { fmt.Fprintf(logWriter, "[ERROR] "+format, args...) }

// ── 获取公网 IP ───────────────────────────────────────────────────────────────

func getNetIface() string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return ""
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "eth") ||
			strings.HasPrefix(name, "ens") ||
			strings.HasPrefix(name, "enp") {
			return name
		}
	}
	return ""
}

func newHTTPClient(network, iface string) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if iface != "" {
		dialer.Control = func(net_, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET,
					syscall.SO_BINDTODEVICE, iface)
			})
		}
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}
}

func getIPFromURL(client *http.Client, url string) string {
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	result := strings.TrimSpace(string(body))
	if net.ParseIP(result) == nil {
		return ""
	}
	return result
}

// getFirstIPConcurrent 并发请求所有 URL，返回最快成功的结果。
// 修复：第一个结果返回后立即取消其余请求，不让输掉的 goroutine 继续等待。
func getFirstIPConcurrent(client *http.Client, urls []string) string {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // 确保函数返回时所有未完成请求都被取消

	type result struct{ ip string }
	ch := make(chan result, len(urls))

	for _, url := range urls {
		url := url
		go func() {
			// 用带 ctx 的请求，cancel() 后会立即中断
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				ch <- result{""}
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				ch <- result{""}
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				ch <- result{""}
				return
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				ch <- result{""}
				return
			}
			ip := strings.TrimSpace(string(body))
			if net.ParseIP(ip) == nil {
				ip = ""
			}
			ch <- result{ip}
		}()
	}

	for range urls {
		if r := <-ch; r.ip != "" {
			cancel() // 立即取消其余请求
			return r.ip
		}
	}
	return ""
}

// initIPInfo 并发探测多个 IP 检测服务，取最快返回的结果。
func initIPInfo(cfg *config.Config) {
	iface := getNetIface()
	ipURLs := []string{
		"http://ip.gs",
		"http://ip.sb",
		"http://ident.me",
		"http://ifconfig.me",
		"http://api.ipify.org",
		"http://icanhazip.com",
	}

	clientV4 := newHTTPClient("tcp4", iface)
	clientV6 := newHTTPClient("tcp6", iface)

	ipv4 := getFirstIPConcurrent(clientV4, ipURLs)
	ipv6 := getFirstIPConcurrent(clientV6, ipURLs)

	if ipv6 != "" && !strings.Contains(ipv6, ":") {
		ipv6 = ""
	}
	proxy.MyIPInfo.Set(ipv4, ipv6)

	if ipv6 != "" && (cfg.PreferIPv6 || ipv4 == "") {
		infof("IPv6 found, using it for external communication\n")
	}
	if ipv4 == "" && ipv6 == "" {
		warnf("Failed to determine your ip\n")
	}
}

// ── 打印代理链接 ──────────────────────────────────────────────────────────────

func printTGInfo(cfg *config.Config) []map[string]string {
	ipv4, ipv6 := proxy.MyIPInfo.Get()
	var ipAddrs []string

	if cfg.MyDomain != "" {
		ipAddrs = []string{cfg.MyDomain}
	} else {
		if ipv4 != "" {
			ipAddrs = append(ipAddrs, ipv4)
		}
		if ipv6 != "" {
			ipAddrs = append(ipAddrs, ipv6)
		}
		if len(ipAddrs) == 0 {
			warnf("Warning: could not determine public IP\n")
			return nil
		}
	}

	defaultSecrets := map[string]bool{
		"00000000000000000000000000000000": true,
		"0123456789abcdef0123456789abcdef": true,
		"00000000000000000000000000000001": true,
	}

	var links []map[string]string
	printDefault := false

	for _, secret := range cfg.Secrets {
		secretHex := hex.EncodeToString(secret)
		for _, ip := range ipAddrs {
			if cfg.Modes.Classic {
				link := fmt.Sprintf("https://t.me/proxy?server=%s&port=%d&secret=%s",
					ip, cfg.Port, secretHex)
				links = append(links, map[string]string{"secret": secretHex, "link": link})
				infof("\033[31mMtproxyurl: %s\033[0m\n", link)
			}
			if cfg.Modes.Secure {
				link := fmt.Sprintf("https://t.me/proxy?server=%s&port=%d&secret=dd%s",
					ip, cfg.Port, secretHex)
				links = append(links, map[string]string{"secret": secretHex, "link": link})
				logf("\033[31mMtproxyurl: %s\033[0m\n", link)
			}
			if cfg.Modes.TLS {
				tlsSecret := "ee" + secretHex + hex.EncodeToString([]byte(cfg.TLSDomain))
				link := fmt.Sprintf("https://t.me/proxy?server=%s&port=%d&secret=%s",
					ip, cfg.Port, tlsSecret)
				links = append(links, map[string]string{"secret": secretHex, "link": link})
				logf("\033[31mMtproxyurl: %s\033[0m\n", link)
			}
		}
		if defaultSecrets[secretHex] {
			warnf("The default secret %s is used, this is not recommended\n", secretHex)
			rnd := crypto.GlobalRand.Bytes(16)
			infof("You can change it to this random secret: %s\n", hex.EncodeToString(rnd))
			printDefault = true
		}
	}

	if cfg.TLSDomain == "www.google.com" {
		warnf("The default TLS_DOMAIN www.google.com is used, this is not recommended\n")
		printDefault = true
	}
	if printDefault {
		warnf("Warning: one or more default settings detected\n")
	}
	return links
}

// ── 服务器启动 ────────────────────────────────────────────────────────────────

// shutdownTimeout 是优雅关闭的最长等待时间。
// 超过此时间后，仍有活跃连接也强制退出，避免因长连接导致进程无法停止。
const shutdownTimeout = 5 * time.Second

func acceptLoop(ln net.Listener, acfg *config.AtomicConfig, wg *sync.WaitGroup) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			proxy.HandleClientWrapper(conn, acfg.Get())
		}()
	}
}

func startServers(acfg *config.AtomicConfig, wg *sync.WaitGroup) []io.Closer {
	cfg := acfg.Get()
	var listeners []io.Closer

	if cfg.ListenAddrIPv4 != "" {
		addr := fmt.Sprintf("%s:%d", cfg.ListenAddrIPv4, cfg.Port)
		ln, err := net.Listen("tcp4", addr)
		if err != nil {
			errorf("Failed to listen on %s: %v\n", addr, err)
		} else {
			infof("Listening on %s\n", addr)
			listeners = append(listeners, ln)
			go acceptLoop(ln, acfg, wg)
		}
	}

	if cfg.ListenAddrIPv6 != "" {
		addr := fmt.Sprintf("[%s]:%d", cfg.ListenAddrIPv6, cfg.Port)
		ln, err := net.Listen("tcp6", addr)
		if err != nil {
			errorf("Failed to listen on %s: %v\n", addr, err)
		} else {
			infof("Listening on %s\n", addr)
			listeners = append(listeners, ln)
			go acceptLoop(ln, acfg, wg)
		}
	}

	if cfg.ListenUnixSock != "" {
		os.Remove(cfg.ListenUnixSock)
		ln, err := net.Listen("unix", cfg.ListenUnixSock)
		if err != nil {
			errorf("Failed to listen on unix %s: %v\n", cfg.ListenUnixSock, err)
		} else {
			listeners = append(listeners, ln)
			go acceptLoop(ln, acfg, wg)
		}
	}

	return listeners
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	setupLogger()
	proxy.SetLogger(logWriter)

	configPath := config.ParseArgs()

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		errorf("配置加载失败: %v\n", err)
		os.Exit(1)
	}

	acfg := config.NewAtomicConfig(cfg)

	proxy.SetLogLevel(cfg.LogLevel)
	proxy.UsedHandshakes = proxy.NewReplayCache(cfg.ReplayCheckLen)
	proxy.ClientIPs = proxy.NewReplayCache(cfg.ClientIPsLen)

	initIPInfo(cfg)
	proxy.SetMaskHost(cfg.MaskHost)
	currentProxyLinks := printTGInfo(cfg)

	go stats.StatsPrinter(cfg, logf)
	go proxy.GetMaskHostCertLen(cfg)
	go proxy.ClearIPResolvingCache()

	if cfg.UseMiddleProxy {
		go proxy.UpdateMiddleProxyInfo(cfg)
	}
	// 直连模式使用硬编码的 DC 地址列表（TGDatacentersV4/V6），
	// Telegram 官方未提供专门的直连 DC 地址更新接口，无需定期刷新。

	stats.StartMetricsServer(cfg, currentProxyLinks)

	var wg sync.WaitGroup

	listeners := startServers(acfg, &wg)
	if len(listeners) == 0 {
		errorf("没有可用的监听地址，退出\n")
		os.Exit(1)
	}

	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGUSR2)
	go func() {
		for range reloadCh {
			newCfg, err := config.LoadConfig(configPath)
			if err != nil {
				errorf("配置重载失败: %v\n", err)
				continue
			}
			acfg.Set(newCfg)
			proxy.SetLogLevel(newCfg.LogLevel)
			proxy.UsedHandshakes = proxy.NewReplayCache(newCfg.ReplayCheckLen)
			proxy.SetMaskHost(newCfg.MaskHost)
			currentProxyLinks = printTGInfo(newCfg)
			infof("Config reloaded\n")
		}
	}()

	// 等待退出信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	infof("Shutting down...\n")

	// 停止接受新连接
	for _, ln := range listeners {
		ln.Close()
	}

	// 等待活跃连接结束，但最多等待 shutdownTimeout。
	// 超时后强制退出，避免长连接导致进程无法停止。
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		infof("All connections closed.\n")
	case <-time.After(shutdownTimeout):
		warnf("Shutdown timeout (%s), forcing exit.\n", shutdownTimeout)
	}

	if logFile != nil {
		logFile.Close()
	}
}
