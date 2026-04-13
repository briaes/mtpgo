package config

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/ini.v1"
)

// ── 握手参数常量 ──────────────────────────────────────────────────────────────

const (
	SkipLen      = 8
	PrekeyLen    = 32
	KeyLen       = 32
	IVLen        = 16
	HandshakeLen = 64
	ProtoTagPos  = 56
	DCIdxPos     = 60
)

// ── 配置结构体 ────────────────────────────────────────────────────────────────

type Modes struct {
	Classic bool
	Secure  bool
	TLS     bool
}

type Config struct {
	Port      int
	Secrets   [][]byte // 所有 secret，每个 16 字节
	ADTag     []byte
	Modes     Modes
	TLSDomain string

	UseMiddleProxy bool
	PreferIPv6     bool
	FastMode       bool
	ProxyProtocol  bool

	Mask     bool
	MaskHost string
	MaskPort int
	MyDomain string

	ListenAddrIPv4 string
	ListenAddrIPv6 string
	ListenUnixSock string

	MetricsPort         int
	MetricsListenAddrV4 string
	MetricsListenAddrV6 string
	MetricsPrefix       string
	MetricsWhitelist    []string
	MetricsExportLinks  bool

	ReplayCheckLen         int
	ClientIPsLen           int
	StatsPrintPeriod       int
	ProxyInfoUpdatePeriod  int
	GetCertLenPeriod       int
	TGConnectTimeout       int
	TGReadTimeout          int
	ClientHandshakeTimeout int
	ClientKeepalive        int
	ClientAckTimeout       int
	IgnoreTimeSkew         bool
	LogLevel               string // debug / info / warn / error
}

// ── 并发安全的配置持有者 ──────────────────────────────────────────────────────

// AtomicConfig 用 RWMutex 保护 Config 的并发读写，解决热重载时的数据竞争。
// 所有 goroutine 通过 Get() 获取当前配置快照，热重载通过 Set() 原子替换。
type AtomicConfig struct {
	mu  sync.RWMutex
	cfg *Config
}

func NewAtomicConfig(cfg *Config) *AtomicConfig {
	return &AtomicConfig{cfg: cfg}
}

// Get 返回当前配置的指针（只读，调用方不得修改）。
func (a *AtomicConfig) Get() *Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg
}

// Set 原子替换配置，热重载时调用。
func (a *AtomicConfig) Set(cfg *Config) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cfg = cfg
}

var secretHexRe = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

func LoadConfig(path string) (*Config, error) {
	cfg := &Config{
		Port:      3256,
		TLSDomain: "www.google.com",
		Modes:     Modes{Classic: true, Secure: true, TLS: true},

		Mask:     true,
		MaskPort: 443,

		ListenAddrIPv4: "0.0.0.0",
		ListenAddrIPv6: "::",

		MetricsPrefix: "mtproxy_",

		ReplayCheckLen:         65536,
		ClientIPsLen:           131072,
		StatsPrintPeriod:       60,
		ProxyInfoUpdatePeriod:  60 * 60,
		GetCertLenPeriod:       4 * 60 * 60,
		TGConnectTimeout:       10,
		TGReadTimeout:          60,
		ClientHandshakeTimeout: 10,
		ClientKeepalive:        10,
		ClientAckTimeout:       10,
		FastMode:               true,
		LogLevel:               "info",
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
	if key, err2 := sec.GetKey("LOG_LEVEL"); err2 == nil {
		v := strings.ToLower(strings.TrimSpace(key.String()))
		switch v {
		case "debug", "info", "warn", "error":
			cfg.LogLevel = v
		default:
			return nil, fmt.Errorf("LOG_LEVEL 无效值 %q，支持: debug/info/warn/error", v)
		}
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
	if key, err2 := sec.GetKey("AD_TAG"); err2 == nil {
		tag, e := hex.DecodeString(key.String())
		if e == nil {
			cfg.ADTag = tag
		}
	}
	if key, err2 := sec.GetKey("METRICS_WHITELIST"); err2 == nil {
		for _, entry := range strings.Split(key.String(), ",") {
			if e := strings.TrimSpace(entry); e != "" {
				cfg.MetricsWhitelist = append(cfg.MetricsWhitelist, e)
			}
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

	// 读取 SECRET（支持逗号分隔多个 32 位 hex 字符串）
	if key, err2 := sec.GetKey("SECRET"); err2 == nil {
		for _, s := range strings.Split(key.String(), ",") {
			s = strings.TrimSpace(s)
			if secretHexRe.MatchString(s) {
				b, _ := hex.DecodeString(s)
				cfg.Secrets = append(cfg.Secrets, b)
			}
		}
	}
	if len(cfg.Secrets) == 0 {
		b, _ := hex.DecodeString("00000000000000000000000000000000")
		cfg.Secrets = append(cfg.Secrets, b)
		fmt.Fprintln(os.Stderr, "警告: 未找到 secret，使用默认值")
	}

	// 范围校验：端口
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("PORT %d 超出有效范围 1-65535", cfg.Port)
	}
	if cfg.MaskPort < 1 || cfg.MaskPort > 65535 {
		return nil, fmt.Errorf("MASK_PORT %d 超出有效范围 1-65535", cfg.MaskPort)
	}
	// 范围校验：超时（秒）
	if cfg.ClientHandshakeTimeout < 1 {
		return nil, fmt.Errorf("CLIENT_HANDSHAKE_TIMEOUT 不能小于 1 秒")
	}
	if cfg.TGReadTimeout < 1 {
		return nil, fmt.Errorf("TG_READ_TIMEOUT 不能小于 1 秒")
	}

	// 默认值推导
	if cfg.MaskHost == "" {
		cfg.MaskHost = cfg.TLSDomain
	}
	cfg.UseMiddleProxy = len(cfg.ADTag) == 16

	return cfg, nil
}

func ParseArgs() (configPath string) {
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
		fmt.Fprintf(os.Stderr, "  -h, --help          显示帮助信息\n")
		fmt.Fprintf(os.Stderr, "  -s, --secret        生成随机 32 位 hex 密钥\n")
		fmt.Fprintf(os.Stderr, "  -c, --config        指定配置文件路径 (默认: <程序目录>/config.ini)\n")
	}

	flag.Parse()

	if showHelp {
		flag.Usage()
		os.Exit(0)
	}

	if genSecret {
		// 修复：使用 crypto/rand 替代 os.Open("/dev/urandom")，跨平台且正确处理错误
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			fmt.Fprintf(os.Stderr, "生成随机 secret 失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(hex.EncodeToString(b))
		os.Exit(0)
	}

	return cfgPath
}
