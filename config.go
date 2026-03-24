package main

import (
	"encoding/hex"
	"flag"
	"strings"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/ini.v1"
)

type Modes struct {
	Classic bool
	Secure  bool
	TLS     bool
}

type Config struct {
	Port       int
	Secrets    [][]byte // 所有 secret，每个 16 字节
	ADTag      []byte
	Modes      Modes
	TLSDomain  string

	UseMiddleProxy bool
	PreferIPv6     bool
	FastMode       bool
	ProxyProtocol  bool

	Mask     bool
	MaskHost string
	MaskPort int
	MyDomain string

	Socks5Host string
	Socks5Port int
	Socks5User string
	Socks5Pass string

	ListenAddrIPv4 string
	ListenAddrIPv6 string
	ListenUnixSock string

	MetricsPort          int
	MetricsListenAddrV4  string
	MetricsListenAddrV6  string
	MetricsPrefix        string
	MetricsWhitelist     []string
	MetricsExportLinks   bool

	ReplayCheckLen  int
	ClientIPsLen    int
	StatsPrintPeriod int
	GetTimePeriod   int
	ProxyInfoUpdatePeriod int
	GetCertLenPeriod int
	TGConnectTimeout int
	TGReadTimeout   int
	ClientHandshakeTimeout int
	ClientKeepalive int
	ClientAckTimeout int
	IgnoreTimeSkew  bool
	Debug           bool

	TOTGBufsize  interface{} // int 或 [3]int
	TOCltBufsize interface{}
}

var secretHexRe = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

func loadConfig(path string) (*Config, error) {
	cfg := &Config{
		Port:      3256,
		TLSDomain: "www.google.com",
		Modes:     Modes{Classic: true, Secure: true, TLS: true},

		Mask:     true,
		MaskPort: 443,

		ListenAddrIPv4: "0.0.0.0",
		ListenAddrIPv6: "::",

		MetricsPrefix: "mtproxy_",

		ReplayCheckLen:        65536,
		ClientIPsLen:          131072,
		StatsPrintPeriod:      60,
		GetTimePeriod:         10 * 60,
		ProxyInfoUpdatePeriod: 60 * 60,
		GetCertLenPeriod:      4 * 60 * 60,
		TGConnectTimeout:      10,
		TGReadTimeout:         60,
		ClientHandshakeTimeout: 10,
		ClientKeepalive:       10,
		ClientAckTimeout:      10,
		FastMode:              true,

		TOTGBufsize:  (1 << 14),
		TOCltBufsize: (1 << 14),
	}

	f, err := ini.Load(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	sec := f.Section("")

	if key, err2 := sec.GetKey("PORT"); err2 == nil {
		cfg.Port, _ = key.Int()
	}
	if key, err2 := sec.GetKey("TLS_DOMAIN"); err2 == nil {
		cfg.TLSDomain = strings.Trim(key.String(), `"'`)
	}
	if key, err2 := sec.GetKey("MASK_HOST"); err2 == nil {
		cfg.MaskHost = key.String()
	}
	if key, err2 := sec.GetKey("MY_DOMAIN"); err2 == nil {
		cfg.MyDomain = key.String()
	}
	if key, err2 := sec.GetKey("MASK_PORT"); err2 == nil {
		cfg.MaskPort, _ = key.Int()
	}
	if key, err2 := sec.GetKey("MASK"); err2 == nil {
		cfg.Mask, _ = key.Bool()
	}
	if key, err2 := sec.GetKey("FAST_MODE"); err2 == nil {
		cfg.FastMode, _ = key.Bool()
	}
	if key, err2 := sec.GetKey("PREFER_IPV6"); err2 == nil {
		cfg.PreferIPv6, _ = key.Bool()
	}
	if key, err2 := sec.GetKey("PROXY_PROTOCOL"); err2 == nil {
		cfg.ProxyProtocol, _ = key.Bool()
	}
	if key, err2 := sec.GetKey("IGNORE_TIME_SKEW"); err2 == nil {
		cfg.IgnoreTimeSkew, _ = key.Bool()
	}
	if key, err2 := sec.GetKey("DEBUG"); err2 == nil {
		cfg.Debug, _ = key.Bool()
	}
	if key, err2 := sec.GetKey("SOCKS5_HOST"); err2 == nil {
		cfg.Socks5Host = key.String()
	}
	if key, err2 := sec.GetKey("SOCKS5_PORT"); err2 == nil {
		cfg.Socks5Port, _ = key.Int()
	}
	if key, err2 := sec.GetKey("SOCKS5_USER"); err2 == nil {
		cfg.Socks5User = key.String()
	}
	if key, err2 := sec.GetKey("SOCKS5_PASS"); err2 == nil {
		cfg.Socks5Pass = key.String()
	}
	if key, err2 := sec.GetKey("LISTEN_ADDR_IPV4"); err2 == nil {
		cfg.ListenAddrIPv4 = key.String()
	}
	if key, err2 := sec.GetKey("LISTEN_ADDR_IPV6"); err2 == nil {
		cfg.ListenAddrIPv6 = key.String()
	}
	if key, err2 := sec.GetKey("LISTEN_UNIX_SOCK"); err2 == nil {
		cfg.ListenUnixSock = key.String()
	}
	if key, err2 := sec.GetKey("METRICS_PORT"); err2 == nil {
		cfg.MetricsPort, _ = key.Int()
	}
	if key, err2 := sec.GetKey("METRICS_LISTEN_ADDR_IPV4"); err2 == nil {
		cfg.MetricsListenAddrV4 = key.String()
	}
	if key, err2 := sec.GetKey("METRICS_LISTEN_ADDR_IPV6"); err2 == nil {
		cfg.MetricsListenAddrV6 = key.String()
	}
	if key, err2 := sec.GetKey("METRICS_PREFIX"); err2 == nil {
		cfg.MetricsPrefix = key.String()
	}
	if key, err2 := sec.GetKey("METRICS_EXPORT_LINKS"); err2 == nil {
		cfg.MetricsExportLinks, _ = key.Bool()
	}
	if key, err2 := sec.GetKey("REPLAY_CHECK_LEN"); err2 == nil {
		cfg.ReplayCheckLen, _ = key.Int()
	}
	if key, err2 := sec.GetKey("CLIENT_IPS_LEN"); err2 == nil {
		cfg.ClientIPsLen, _ = key.Int()
	}
	if key, err2 := sec.GetKey("STATS_PRINT_PERIOD"); err2 == nil {
		cfg.StatsPrintPeriod, _ = key.Int()
	}
	if key, err2 := sec.GetKey("GET_TIME_PERIOD"); err2 == nil {
		cfg.GetTimePeriod, _ = key.Int()
	}
	if key, err2 := sec.GetKey("AD_TAG"); err2 == nil {
		tag, e := hex.DecodeString(key.String())
		if e == nil {
			cfg.ADTag = tag
		}
	}

	// 读取 MODES
	if key, err2 := sec.GetKey("MODES_CLASSIC"); err2 == nil {
		cfg.Modes.Classic, _ = key.Bool()
	}
	if key, err2 := sec.GetKey("MODES_SECURE"); err2 == nil {
		cfg.Modes.Secure, _ = key.Bool()
	}
	if key, err2 := sec.GetKey("MODES_TLS"); err2 == nil {
		cfg.Modes.TLS, _ = key.Bool()
	}

	// 收集所有独立 secret 变量（32位hex字符串）
	reservedKeys := map[string]bool{
		"PORT": true, "AD_TAG": true, "USE_MIDDLE_PROXY": true, "PREFER_IPV6": true,
		"FAST_MODE": true, "PROXY_PROTOCOL": true, "TLS_DOMAIN": true, "MASK": true,
		"MASK_HOST": true, "MY_DOMAIN": true, "MASK_PORT": true, "SOCKS5_HOST": true,
		"SOCKS5_PORT": true, "SOCKS5_USER": true, "SOCKS5_PASS": true,
		"LISTEN_ADDR_IPV4": true, "LISTEN_ADDR_IPV6": true, "LISTEN_UNIX_SOCK": true,
		"METRICS_PORT": true, "METRICS_LISTEN_ADDR_IPV4": true, "METRICS_LISTEN_ADDR_IPV6": true,
		"METRICS_PREFIX": true, "METRICS_EXPORT_LINKS": true, "METRICS_WHITELIST": true,
		"REPLAY_CHECK_LEN": true, "CLIENT_IPS_LEN": true, "STATS_PRINT_PERIOD": true,
		"GET_TIME_PERIOD": true, "MODES_CLASSIC": true, "MODES_SECURE": true, "MODES_TLS": true,
		"IGNORE_TIME_SKEW": true,
	}
	for _, key := range sec.Keys() {
		name := key.Name()
		val := key.String()
		if reservedKeys[name] {
			continue
		}
		if secretHexRe.MatchString(val) {
			b, _ := hex.DecodeString(val)
			cfg.Secrets = append(cfg.Secrets, b)
		}
	}
	if len(cfg.Secrets) == 0 {
		b, _ := hex.DecodeString("00000000000000000000000000000000")
		cfg.Secrets = append(cfg.Secrets, b)
		fmt.Fprintln(os.Stderr, "警告: 未找到 secret，使用默认值")
	}

	// 默认值推导
	if cfg.MaskHost == "" {
		cfg.MaskHost = cfg.TLSDomain
	}
	cfg.UseMiddleProxy = len(cfg.ADTag) == 16
	if cfg.Socks5Host != "" && cfg.Socks5Port != 0 {
		cfg.UseMiddleProxy = false
	}

	return cfg, nil
}

func parseArgs() (configPath string) {
	defaultConfig := filepath.Join(filepath.Dir(os.Args[0]), "config.ini")

	var cfgPath string
	var genSecret bool
	var showHelp bool

	flag.StringVar(&cfgPath, "c", defaultConfig, "")
	flag.StringVar(&cfgPath, "config", defaultConfig, "")
	flag.BoolVar(&genSecret, "s", false, "")
	flag.BoolVar(&genSecret, "secret", false, "")
	flag.BoolVar(&showHelp, "h", false, "")
	flag.BoolVar(&showHelp, "help", false, "")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -s, --secret        生成随机 32 位 hex 密钥\n")
		fmt.Fprintf(os.Stderr, "  -c, --config        指定配置文件路径 (默认: <程序目录>/config.ini)\n")
		fmt.Fprintf(os.Stderr, "  -h, --help          显示帮助信息\n")
	}

	flag.Parse()

	if showHelp {
		flag.Usage()
		os.Exit(0)
	}

	if genSecret {
		b := make([]byte, 16)
		f, _ := os.Open("/dev/urandom")
		f.Read(b)
		f.Close()
		fmt.Println(hex.EncodeToString(b))
		os.Exit(0)
	}

	return cfgPath
}
