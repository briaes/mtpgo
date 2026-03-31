package main

import (
	"encoding/hex"
	"fmt"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// ── 日志 ──────────────────────────────────────────────────────────────────────

var logWriter io.Writer = os.Stderr

func setupLogger() {
	logDir := filepath.Dir(os.Args[0])
	logPath := filepath.Join(logDir, "log_mtpgo")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法创建日志文件 %s: %v\n", logPath, err)
		return
	}
	logWriter = io.MultiWriter(os.Stderr, logFile)
}

func logf(format string, args ...interface{}) {
	fmt.Fprintf(logWriter, format, args...)
}

func dbgf(cfg *Config, format string, args ...interface{}) {
	if cfg != nil && cfg.Debug {
		logf(format, args...)
	}
}

// ── 获取公网 IP ───────────────────────────────────────────────────────────────

// getNetIface 获取第一个物理网卡名（eth/ens/enp 开头）
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

// newHTTPClient 创建强制使用指定 IP 版本和网卡的 HTTP 客户端
// network: "tcp4" 强制 IPv4，"tcp6" 强制 IPv6
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

// getIPFromURL 请求 URL 并返回合法 IP，失败返回空字符串
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

// getFirstIP 依次尝试 URL 列表，返回第一个成功的 IP
func getFirstIP(client *http.Client, urls []string) string {
	for _, url := range urls {
		if ip := getIPFromURL(client, url); ip != "" {
			return ip
		}
	}
	return ""
}

func initIPInfo(cfg *Config) {
	iface := getNetIface()

	// 同一套 URL，分别强制走 IPv4/IPv6 网络连接
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

	ipv4 := getFirstIP(clientV4, ipURLs)
	ipv6 := getFirstIP(clientV6, ipURLs)

	// 额外验证 IPv6 格式（包含 : 才是合法 IPv6）
	if ipv6 != "" && !strings.Contains(ipv6, ":") {
		ipv6 = ""
	}

	myIPInfo.Set(ipv4, ipv6)

	if ipv6 != "" && (cfg.PreferIPv6 || ipv4 == "") {
		logf("IPv6 found, using it for external communication\n")
	}
	if cfg.UseMiddleProxy && ipv4 == "" && ipv6 == "" {
		logf("Failed to determine your ip, advertising disabled\n")
		disableMiddleProxy = true
	}
}

// ── 打印代理链接 ──────────────────────────────────────────────────────────────

var currentProxyLinks []map[string]string

func printTGInfo(cfg *Config) []map[string]string {
	ipv4, ipv6 := myIPInfo.Get()
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
			logf("Warning: could not determine public IP\n")
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
				logf("\033[31mMtproxyurl: %s\033[0m\n", link)
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
			logf("The default secret %s is used, this is not recommended\n", secretHex)
			rnd := globalRand.Bytes(16)
			logf("You can change it to this random secret: %s\n", hex.EncodeToString(rnd))
			printDefault = true
		}
	}

	if cfg.TLSDomain == "www.google.com" {
		logf("The default TLS_DOMAIN www.google.com is used, this is not recommended\n")
		printDefault = true
	}
	if printDefault {
		logf("Warning: one or more default settings detected\n")
	}

	return links
}

// ── 服务器启动 ────────────────────────────────────────────────────────────────

func startServers(cfg *Config) []io.Closer {
	var listeners []io.Closer

	if cfg.ListenAddrIPv4 != "" {
		addr := fmt.Sprintf("%s:%d", cfg.ListenAddrIPv4, cfg.Port)
		ln, err := net.Listen("tcp4", addr)
		if err != nil {
			logf("Failed to listen on %s: %v\n", addr, err)
		} else {
			logf("Listening on %s\n", addr)
			listeners = append(listeners, ln)
			go acceptLoop(ln, cfg)
		}
	}

	if cfg.ListenAddrIPv6 != "" {
		addr := fmt.Sprintf("[%s]:%d", cfg.ListenAddrIPv6, cfg.Port)
		ln, err := net.Listen("tcp6", addr)
		if err != nil {
			logf("Failed to listen on %s: %v\n", addr, err)
		} else {
			logf("Listening on %s\n", addr)
			listeners = append(listeners, ln)
			go acceptLoop(ln, cfg)
		}
	}

	if cfg.ListenUnixSock != "" {
		os.Remove(cfg.ListenUnixSock)
		ln, err := net.Listen("unix", cfg.ListenUnixSock)
		if err != nil {
			logf("Failed to listen on unix %s: %v\n", cfg.ListenUnixSock, err)
		} else {
			listeners = append(listeners, ln)
			go acceptLoop(ln, cfg)
		}
	}

	return listeners
}

func acceptLoop(ln net.Listener, cfg *Config) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleClientWrapper(conn, cfg)
	}
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	setupLogger()
	configPath := parseArgs()

	cfg, err := loadConfig(configPath)
	if err != nil {
		logf("配置加载失败: %v\n", err)
		os.Exit(1)
	}

	usedHandshakes = newReplayCache(cfg.ReplayCheckLen)
	clientIPs = newReplayCache(cfg.ClientIPsLen)

	initIPInfo(cfg)
	currentProxyLinks = printTGInfo(cfg)

	go statsPrinter(cfg)
	go getMaskHostCertLen(cfg)
	go clearIPResolvingCache()

	if cfg.UseMiddleProxy {
		go updateMiddleProxyInfo(cfg)
		if cfg.GetTimePeriod > 0 {
			go getSrvTime(cfg)
		}
	}

	startMetricsServer(cfg, currentProxyLinks)

	listeners := startServers(cfg)
	if len(listeners) == 0 {
		logf("没有可用的监听地址，退出\n")
		os.Exit(1)
	}

	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGUSR2)
	go func() {
		for range reloadCh {
			newCfg, err := loadConfig(configPath)
			if err != nil {
				logf("配置重载失败: %v\n", err)
				continue
			}
			*cfg = *newCfg
			usedHandshakes = newReplayCache(cfg.ReplayCheckLen)
			currentProxyLinks = printTGInfo(cfg)
			logf("Config reloaded\n")
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logf("Shutting down...\n")
	for _, ln := range listeners {
		ln.Close()
	}
}
