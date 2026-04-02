package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"mtproxy/config"
	"mtproxy/crypto"
	"mtproxy/proto"
)

// ── TLS ClientHello 指纹验证 ──────────────────────────────────────────────────
//
// 同时计算 JA3 和 JA4 指纹，对命中黑名单的扫描器/探针直接拒绝连接。
// 指纹验证仅在 TLS 模式（fake-TLS/EE 模式）下生效；
// Classic 和 Secure 模式的连接不经过此函数，由握手加密层自身保护。
//
// JA3：TLSVersion,Ciphers,Extensions,EllipticCurves,PointFormats → SHA-256[:16]
//   特点：受 extension 随机化影响，但扫描器 TLS 库固定，适合黑名单过滤。
//
// JA4：t<tlsVer><sni><cc><ec><alpn>_<cipherHash>_<extHash>
//   特点：对 ciphers/extensions 排序后再 hash，不受随机化影响，更稳定。
//   格式参考：https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
//
// 注意：blockedJA3 使用的是 SHA-256[:16] hex，而非标准 JA3 的 MD5，
// 两者不兼容，不能直接复用外部 JA3 数据库中的 hash 值。

// ── 黑名单 ────────────────────────────────────────────────────────────────────

// blockedJA3 收录特征固定的扫描器/探针 JA3 指纹。
// ⚠️  此处使用 SHA-256[:16] hex（非标准 MD5），不与外部 JA3 数据库兼容。
var blockedJA3 = map[string]bool{
	// Python requests / urllib3（默认 OpenSSL）
	"6197d86df921e23305fb68d5f6a31d3a": true,
	"e6573e91e6eb777c0933c5b8f97f10cd": true,
	// Go net/http 标准库
	"70bc9b2e5ec3b5f25bdfa59a22c2b5c7": true,
	"dad6c8d267b2b91cfec3769f46c9570e": true,
	// curl（默认 OpenSSL 构建）
	"7dc465e2662c04da97b61b616febb95e": true,
	"fd6d5a7f3a6a2c5cdd25b25d0dc3b5db": true,
	// Java HttpURLConnection / OkHttp 默认
	"93ecead4d88d27c8b09e3f67d31df2e0": true,
	// Nmap / ZMap / masscan TLS 探针
	"8b4b4a8e3e8cd69b47f4fd61a3da9fba": true,
	"1aa7bf8b03c0b6a39a47e42d4b5c2c6d": true,
	// Zgrab2 / censys 扫描器
	"11a7f5f64605e8e1b3eb0d0c98d4e58e": true,
	"4f4fbe2cf90c38b0c2c97bc59e08a4e3": true,
	// Shodan 爬虫
	"6bea09da78ded4726e2f0c015e757a68": true,
}

// blockedJA4Prefixes 收录扫描器/探针的 JA4 前缀。
// 前缀精确到 "<proto><tlsVer><sni><cc><ec><alpn>_<cipherHash>" 级别（含首段 hash），
// 避免仅凭 cc/ec 数量误拦合法客户端。
// 空 cipher 列表的畸形包 cipherHash 固定为 e3b0c44298fc（SHA-256("") 前6字节），
// 直接加入黑名单。
var blockedJA4Prefixes = []string{
	// curl（无 SNI，TLS 1.3，2 cipher，cipherHash 固定）
	"t13i0200h2_",
	"t13i020000_",
	// curl（无 SNI，TLS 1.2）
	"t12i0200h1_",
	"t12i020000_",
	// Python requests（无 SNI，TLS 1.3，5 cipher）
	"t13i0500h2_",
	"t13i050000_",
	// Python requests（无 SNI，TLS 1.2）
	"t12i0500h1_",
	"t12i050000_",
	// Go net/http（无 SNI，TLS 1.3，3 cipher）
	"t13i0300h2_",
	"t13i030000_",
	// Zgrab2 / masscan（无 SNI，极简 cipher）
	"t13i0100__",
	"t12i0100__",
	// 畸形包：空 cipher 列表，cipherHash = SHA-256("") 前6字节
	"t13i" + "____e3b0c44298fc",
	"t12i" + "____e3b0c44298fc",
}

// ── 解析结构 ──────────────────────────────────────────────────────────────────

// tlsHello 是解析 ClientHello 后的中间结构，供 JA3/JA4 共用，避免重复遍历。
type tlsHello struct {
	legacyVer   uint16
	ciphers     []uint16 // 已过滤 GREASE，保留原始顺序（JA3 用）
	extTypes    []uint16 // 已过滤 GREASE，保留原始顺序（JA3 用）
	curves      []uint16
	pointFmts   []byte
	sniPresent  bool
	alpn        string // 第一个 ALPN 值，如 "h2"、"http/1.1"
	maxTLSVer   uint16 // supported_versions 中最高版本（0 表示未出现此 extension）
	extCount    int    // 去 GREASE 后的 extension 数量
	cipherCount int
}

// parseClientHello 解析 TLS ClientHello（不含 5 字节记录层头），
// 返回供 JA3/JA4 使用的中间结构。
func parseClientHello(hello []byte) (*tlsHello, error) {
	if len(hello) < 38 {
		return nil, fmt.Errorf("ClientHello too short")
	}
	if hello[0] != 0x01 {
		return nil, fmt.Errorf("not a ClientHello")
	}
	pos := 4 // type(1) + length(3)
	if pos+2 > len(hello) {
		return nil, fmt.Errorf("truncated at version")
	}
	h := &tlsHello{}
	h.legacyVer = binary.BigEndian.Uint16(hello[pos:])
	pos += 2
	pos += 32 // random
	if pos >= len(hello) {
		return nil, fmt.Errorf("truncated at session id")
	}
	pos += 1 + int(hello[pos]) // session id
	if pos+2 > len(hello) {
		return nil, fmt.Errorf("truncated at cipher suites")
	}
	csLen := int(binary.BigEndian.Uint16(hello[pos:]))
	pos += 2
	if pos+csLen > len(hello) {
		return nil, fmt.Errorf("truncated cipher suite list")
	}
	for i := 0; i < csLen; i += 2 {
		cs := binary.BigEndian.Uint16(hello[pos+i:])
		if isGREASE(cs) || cs == 0x0000 {
			continue
		}
		h.ciphers = append(h.ciphers, cs)
	}
	h.cipherCount = len(h.ciphers)
	pos += csLen
	if pos >= len(hello) {
		return nil, fmt.Errorf("truncated at compression")
	}
	pos += 1 + int(hello[pos]) // compression methods
	if pos+2 > len(hello) {
		return h, nil // no extensions — 合法但罕见
	}
	extTotalLen := int(binary.BigEndian.Uint16(hello[pos:]))
	pos += 2
	extEnd := pos + extTotalLen
	if extEnd > len(hello) {
		extEnd = len(hello)
	}
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(hello[pos:])
		extLen := int(binary.BigEndian.Uint16(hello[pos+2:]))
		pos += 4
		end := pos + extLen
		if end > extEnd {
			end = extEnd
		}
		extData := hello[pos:end]
		pos += extLen
		if isGREASE(extType) {
			continue
		}
		h.extTypes = append(h.extTypes, extType)
		switch extType {
		case 0x0000: // server_name
			h.sniPresent = true
		case 0x000a: // supported_groups
			if len(extData) >= 2 {
				listLen := int(binary.BigEndian.Uint16(extData))
				for i := 2; i+1 < 2+listLen && i+1 < len(extData); i += 2 {
					g := binary.BigEndian.Uint16(extData[i:])
					if !isGREASE(g) {
						h.curves = append(h.curves, g)
					}
				}
			}
		case 0x000b: // ec_point_formats
			if len(extData) >= 1 {
				fmtLen := int(extData[0])
				for i := 1; i <= fmtLen && i < len(extData); i++ {
					h.pointFmts = append(h.pointFmts, extData[i])
				}
			}
		case 0x0010: // application_layer_protocol_negotiation
			// list_len(2) + first_proto: proto_len(2) + proto_bytes
			if len(extData) >= 4 {
				protoLen := int(binary.BigEndian.Uint16(extData[2:]))
				if 4+protoLen <= len(extData) {
					h.alpn = string(extData[4 : 4+protoLen])
				}
			}
		case 0x002b: // supported_versions
			if len(extData) >= 1 {
				listLen := int(extData[0])
				for i := 1; i+1 < 1+listLen && i+1 < len(extData); i += 2 {
					v := binary.BigEndian.Uint16(extData[i:])
					if !isGREASE(v) && v > h.maxTLSVer {
						h.maxTLSVer = v
					}
				}
			}
		}
	}
	h.extCount = len(h.extTypes)
	return h, nil
}

func isGREASE(v uint16) bool {
	// GREASE 值形如 0x?A?A，其中 ? 为相同的半字节，参见 RFC 8701
	return v&0x0f0f == 0x0a0a
}

// ── JA3 ───────────────────────────────────────────────────────────────────────

func parseClientHelloJA3(hello []byte) (string, error) {
	h, err := parseClientHello(hello)
	if err != nil {
		return "", err
	}
	return buildJA3(h), nil
}

func buildJA3(h *tlsHello) string {
	join16 := func(vals []uint16) string {
		if len(vals) == 0 {
			return ""
		}
		s := fmt.Sprintf("%d", vals[0])
		for _, v := range vals[1:] {
			s += fmt.Sprintf("-%d", v)
		}
		return s
	}
	joinB := func(vals []byte) string {
		if len(vals) == 0 {
			return ""
		}
		s := fmt.Sprintf("%d", vals[0])
		for _, v := range vals[1:] {
			s += fmt.Sprintf("-%d", v)
		}
		return s
	}
	raw := fmt.Sprintf("%d,%s,%s,%s,%s",
		h.legacyVer, join16(h.ciphers), join16(h.extTypes),
		join16(h.curves), joinB(h.pointFmts))
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum[:16])
}

// ── JA4 ───────────────────────────────────────────────────────────────────────

func parseClientHelloJA4(hello []byte) (string, error) {
	h, err := parseClientHello(hello)
	if err != nil {
		return "", err
	}
	return buildJA4(h), nil
}

// buildJA4 按 JA4 规范构造指纹字符串：
//
//	t<tlsVer><sni><cc><ec><alpn>_<cipherHash>_<extHash>
//
//	tlsVer     : 从 supported_versions 取最高版本；13/12/11/10；无则取 legacyVer
//	sni        : 'd'(有域名SNI) 或 'i'(无SNI或IP直连)
//	cc/ec      : cipher/extension 数量，两位十进制，上限 99
//	alpn       : 首个 ALPN 协议名的首尾字符；无则 "00"
//	cipherHash : 排序后 cipher 列表的 SHA-256[:6] hex
//	extHash    : 排序后 extension 列表（去除SNI/ALPN）的 SHA-256[:6] hex
func buildJA4(h *tlsHello) string {
	// TLS 版本：优先使用 supported_versions extension 中的最高版本
	v := h.maxTLSVer
	if v == 0 {
		v = h.legacyVer
	}
	var tlsVerStr string
	switch v {
	case 0x0304:
		tlsVerStr = "13"
	case 0x0303:
		tlsVerStr = "12"
	case 0x0302:
		tlsVerStr = "11"
	case 0x0301:
		tlsVerStr = "10"
	default:
		tlsVerStr = fmt.Sprintf("%02x", v&0xff)
	}

	// SNI
	sni := "i"
	if h.sniPresent {
		sni = "d"
	}

	// cipher / extension 数量（上限 99）
	cc := h.cipherCount
	if cc > 99 {
		cc = 99
	}
	ec := h.extCount
	if ec > 99 {
		ec = 99
	}

	// ALPN 首尾字符；"h2" → "h2"，"http/1.1" → "h1"，无则 "00"
	alpnTag := "00"
	if h.alpn != "" {
		if len(h.alpn) == 1 {
			alpnTag = string(h.alpn[0]) + string(h.alpn[0])
		} else {
			alpnTag = string(h.alpn[0]) + string(h.alpn[len(h.alpn)-1])
		}
	}

	// 排序后的 cipher hash
	sortedCiphers := make([]uint16, len(h.ciphers))
	copy(sortedCiphers, h.ciphers)
	sortUint16(sortedCiphers)
	cipherHash := hashList16(sortedCiphers)

	// 排序后的 extension hash（规范要求排除 SNI=0x0000 和 ALPN=0x0010）
	var extsForHash []uint16
	for _, e := range h.extTypes {
		if e != 0x0000 && e != 0x0010 {
			extsForHash = append(extsForHash, e)
		}
	}
	sortUint16(extsForHash)
	extHash := hashList16(extsForHash)

	prefix := fmt.Sprintf("t%s%s%02d%02d%s", tlsVerStr, sni, cc, ec, alpnTag)
	return fmt.Sprintf("%s_%s_%s", prefix, cipherHash, extHash)
}

func sortUint16(s []uint16) {
	// 插入排序；cipher/extension 列表通常 ≤ 20 项，插入排序足够快
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// hashList16 将 uint16 切片以大端字节序拼接后取 SHA-256[:6] hex（12字符）。
// 空切片返回 SHA-256("") 的前 6 字节 hex = "e3b0c44298fc"，
// 此值已加入 blockedJA4Prefixes，用于识别 cipher 列表为空的畸形探测包。
func hashList16(vals []uint16) string {
	var b []byte
	for _, v := range vals {
		b = append(b, byte(v>>8), byte(v))
	}
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h[:6])
}

// ── 统一验证入口 ──────────────────────────────────────────────────────────────

// verifyTLSFingerprint 对 fake-TLS 握手中的 ClientHello 进行双重指纹检查：
//  1. JA3 黑名单（hash 精确匹配）
//  2. JA4 前缀黑名单（前缀匹配，精确到 cipherHash 段）
//  3. 最低 TLS 版本检查（拒绝 TLS 1.1 及以下）
//
// 任一检查失败则返回 false（拒绝连接）。
// 此函数仅在 TLS 模式下调用，Classic/Secure 模式不经过此验证。
func verifyTLSFingerprint(hello []byte, cfg *config.Config) bool {
	h, err := parseClientHello(hello)
	if err != nil {
		Dbgf(cfg, "[TLS-FP] parse error: %v\n", err)
		return false
	}

	// 检查 1：最低 TLS 版本（拒绝 TLS 1.1 及以下，扫描器常用旧协议探测）
	v := h.maxTLSVer
	if v == 0 {
		v = h.legacyVer
	}
	if v != 0 && v < 0x0303 {
		Dbgf(cfg, "[TLS-FP] rejected old TLS version: 0x%04x\n", v)
		return false
	}

	ja3 := buildJA3(h)
	ja4 := buildJA4(h)
	Dbgf(cfg, "[TLS-FP] JA3=%s JA4=%s\n", ja3, ja4)

	// 检查 2：JA3 黑名单（精确匹配）
	if blockedJA3[ja3] {
		Dbgf(cfg, "[TLS-FP] blocked by JA3: %s\n", ja3)
		return false
	}

	// 检查 3：JA4 前缀黑名单
	for _, prefix := range blockedJA4Prefixes {
		if len(ja4) >= len(prefix) && ja4[:len(prefix)] == prefix {
			Dbgf(cfg, "[TLS-FP] blocked by JA4 prefix %q: %s\n", prefix, ja4)
			return false
		}
	}

	return true
}

// ── Replay 防护 ───────────────────────────────────────────────────────────────

type replayCache struct {
	mu     sync.Mutex
	cache  map[string]bool
	order  []string
	maxLen int
}

func NewReplayCache(maxLen int) *replayCache {
	return &replayCache{cache: make(map[string]bool), maxLen: maxLen}
}

func (rc *replayCache) Has(key []byte) bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.cache[string(key)]
}

func (rc *replayCache) Add(key []byte) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.maxLen > 0 && len(rc.order) >= rc.maxLen {
		oldest := rc.order[0]
		rc.order = rc.order[1:]
		delete(rc.cache, oldest)
	}
	k := string(key)
	rc.cache[k] = true
	rc.order = append(rc.order, k)
}

var UsedHandshakes *replayCache
var ClientIPs *replayCache

// ── 握手结果 ──────────────────────────────────────────────────────────────────

type HandshakeResult struct {
	Reader    proto.StreamReader
	Writer    proto.StreamWriter
	ProtoTag  []byte
	SecretHex string
	DcIdx     int
	EncKeyIV  []byte
	Peer      net.Addr
}

// ── TLS 伪装握手 ──────────────────────────────────────────────────────────────

func handleFakeTLSHandshake(handshake []byte, reader proto.StreamReader, writer proto.StreamWriter,
	peer net.Addr, cfg *config.Config) (proto.StreamReader, proto.StreamWriter, error) {

	const (
		digestLen     = 32
		digestHalfLen = 16
		digestPos     = 11
	)

	sessionIDLenPos := digestPos + digestLen
	sessionIDPos := sessionIDLenPos + 1

	tlsVers := []byte{0x03, 0x03}
	tlsCiphersuite := []byte{0x13, 0x01}
	tlsChangeCipher := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
	tlsAppHTTP2Hdr := []byte{0x17, 0x03, 0x03}

	tlsExtensions := []byte{0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20}
	tlsExtensions = append(tlsExtensions, crypto.GlobalRand.GenX25519PublicKey()...)
	tlsExtensions = append(tlsExtensions, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)

	digest := handshake[digestPos : digestPos+digestLen]

	if UsedHandshakes.Has(digest[:digestHalfLen]) {
		return nil, nil, fmt.Errorf("duplicate handshake")
	}

	// ── TLS 指纹验证 ──────────────────────────────────────────────────────────
	// handshake[4:] 是 ClientHello 报文体（已跳过 5 字节记录层头）。
	// 指纹不合法时直接拒绝，不继续尝试 secret 匹配，减少信息泄露。
	if len(handshake) < 6 {
		return nil, nil, fmt.Errorf("handshake too short for fingerprint")
	}
	if !verifyTLSFingerprint(handshake[5:], cfg) {
		return nil, nil, fmt.Errorf("TLS fingerprint rejected")
	}

	sessIDLen := int(handshake[sessionIDLenPos])
	sessID := handshake[sessionIDPos : sessionIDPos+sessIDLen]

	Dbgf(cfg, "[DEBUG] TLS handshake: handshake len=%d digestPos=%d digest=%x\n",
		len(handshake), digestPos, digest[:8])

	for _, secret := range cfg.Secrets {
		msg := make([]byte, len(handshake))
		copy(msg, handshake)
		for i := digestPos; i < digestPos+digestLen; i++ {
			msg[i] = 0
		}

		mac := hmac.New(sha256.New, secret)
		mac.Write(msg)
		computedDigest := mac.Sum(nil)

		xored := make([]byte, digestLen)
		for i := range xored {
			xored[i] = digest[i] ^ computedDigest[i]
		}

		Dbgf(cfg, "[DEBUG] TLS xored[:4]=%x (want 00000000)\n", xored[:4])

		// 检查前 28 字节是否为 0
		allZero := true
		for _, b := range xored[:digestLen-4] {
			if b != 0 {
				allZero = false
				break
			}
		}
		if !allZero {
			continue
		}

		timestamp := int64(binary.LittleEndian.Uint32(xored[digestLen-4:]))
		now := time.Now().Unix()
		skew := now - timestamp
		const timeSkewMin = -20 * 60
		const timeSkewMax = 10 * 60
		clientTimeOK := skew > timeSkewMin && skew < timeSkewMax
		clientTimeSmall := timestamp < 60*60*24*1000
		Dbgf(cfg, "[DEBUG] TLS timestamp=%d now=%d skew=%d ok=%v\n", timestamp, now, skew, clientTimeOK)
		if !clientTimeOK && !cfg.IgnoreTimeSkew && !clientTimeSmall {
			continue
		}

		fakeCertLen := rand.Intn(4096-1024) + 1024
		httpData := crypto.GlobalRand.Bytes(fakeCertLen)

		srvHello := append(tlsVers, make([]byte, digestLen)...)
		srvHello = append(srvHello, byte(sessIDLen))
		srvHello = append(srvHello, sessID...)
		srvHello = append(srvHello, tlsCiphersuite...)
		srvHello = append(srvHello, 0x00)
		srvHello = append(srvHello, tlsExtensions...)

		srvHelloInnerLen := make([]byte, 3)
		srvHelloInnerLen[0] = byte(len(srvHello) >> 16)
		srvHelloInnerLen[1] = byte(len(srvHello) >> 8)
		srvHelloInnerLen[2] = byte(len(srvHello))
		outerLen := len(srvHello) + 4
		helloPkt := []byte{0x16, 0x03, 0x03, byte(outerLen >> 8), byte(outerLen)}
		helloPkt = append(helloPkt, 0x02)
		helloPkt = append(helloPkt, srvHelloInnerLen...)
		helloPkt = append(helloPkt, srvHello...)
		helloPkt = append(helloPkt, tlsChangeCipher...)
		helloPkt = append(helloPkt, tlsAppHTTP2Hdr...)
		helloPkt = append(helloPkt, byte(len(httpData)>>8), byte(len(httpData)))
		helloPkt = append(helloPkt, httpData...)

		mac2 := hmac.New(sha256.New, secret)
		mac2.Write(digest)
		mac2.Write(helloPkt)
		computedDigest2 := mac2.Sum(nil)
		copy(helloPkt[digestPos:], computedDigest2)

		if err := writer.Write(helloPkt, nil); err != nil {
			return nil, nil, err
		}

		if cfg.ReplayCheckLen > 0 {
			UsedHandshakes.Add(digest[:digestHalfLen])
		}

		return &proto.FakeTLSReader{Upstream: reader}, &proto.FakeTLSWriter{Upstream: writer}, nil
	}

	return nil, nil, fmt.Errorf("no matching secret")
}

// ── 主握手处理 ────────────────────────────────────────────────────────────────

func HandleHandshake(conn net.Conn, cfg *config.Config) (*HandshakeResult, []byte, error) {
	tlsStartBytes := []byte{0x16, 0x03, 0x01}

	reader := &proto.TCPReader{Conn: conn}
	writer := &proto.TCPWriter{Conn: conn}

	// proxy protocol 解析
	var peerAddr net.Addr = conn.RemoteAddr()
	if cfg.ProxyProtocol {
		var err2 error
		peerAddr, err2 = proto.HandleProxyProtocol(reader, peerAddr)
		if err2 != nil || peerAddr == nil {
			return nil, nil, fmt.Errorf("bad proxy protocol header: %v", err2)
		}
	}

	var handshake []byte
	isTLS := true

	for _, expected := range tlsStartBytes {
		b, err := reader.ReadExactly(1)
		if err != nil {
			return nil, nil, err
		}
		handshake = append(handshake, b...)
		if b[0] != expected {
			isTLS = false
			break
		}
	}

	if isTLS {
		lenBytes, err := reader.ReadExactly(2)
		if err != nil {
			return nil, nil, err
		}
		handshake = append(handshake, lenBytes...)
		tlsLen := int(binary.BigEndian.Uint16(lenBytes))
		if tlsLen < 512 {
			isTLS = false
		} else {
			body, err := reader.ReadExactly(tlsLen)
			if err != nil {
				return nil, nil, err
			}
			handshake = append(handshake, body...)
		}
	}

	var sr proto.StreamReader = reader
	var sw proto.StreamWriter = writer

	if isTLS {
		newReader, newWriter, err := handleFakeTLSHandshake(handshake, sr, sw, conn.RemoteAddr(), cfg)
		if err != nil {
			return nil, handshake, fmt.Errorf("tls handshake failed: %w", err)
		}
		sr = newReader
		sw = newWriter
		hs, err := sr.ReadExactly(config.HandshakeLen)
		if err != nil {
			return nil, nil, err
		}
		handshake = hs
	} else {
		if !cfg.Modes.Classic && !cfg.Modes.Secure {
			return nil, handshake, fmt.Errorf("classic/secure modes disabled")
		}
		rest, err := sr.ReadExactly(config.HandshakeLen - len(handshake))
		if err != nil {
			return nil, nil, err
		}
		handshake = append(handshake, rest...)
	}

	decPrekeyAndIV := handshake[config.SkipLen : config.SkipLen+config.PrekeyLen+config.IVLen]
	decPrekey := decPrekeyAndIV[:config.PrekeyLen]
	decIV := decPrekeyAndIV[config.PrekeyLen:]

	encPrekeyAndIV := make([]byte, len(decPrekeyAndIV))
	copy(encPrekeyAndIV, decPrekeyAndIV)
	ReverseBytes(encPrekeyAndIV)
	encPrekey := encPrekeyAndIV[:config.PrekeyLen]
	encIV := encPrekeyAndIV[config.PrekeyLen:]

	if cfg.ReplayCheckLen > 0 && UsedHandshakes.Has(decPrekeyAndIV) {
		return nil, handshake, fmt.Errorf("replay detected")
	}

	for _, secret := range cfg.Secrets {
		decInput := make([]byte, len(decPrekey)+len(secret))
		copy(decInput, decPrekey)
		copy(decInput[len(decPrekey):], secret)
		decKeyRaw := sha256.Sum256(decInput)
		decKey := decKeyRaw[:]
		decIV16 := make([]byte, 16)
		copy(decIV16, decIV)

		encInput := make([]byte, len(encPrekey)+len(secret))
		copy(encInput, encPrekey)
		copy(encInput[len(encPrekey):], secret)
		encKeyRaw := sha256.Sum256(encInput)
		encKey := encKeyRaw[:]
		encIV16 := make([]byte, 16)
		copy(encIV16, encIV)

		streamDecryptorTmp := crypto.NewAESCTR(decKey, crypto.Uint128FromBytes(decIV16))
		decrypted := streamDecryptorTmp.Decrypt(handshake)

		protoTag := decrypted[config.ProtoTagPos : config.ProtoTagPos+4]

		isAbridged := bytes.Equal(protoTag, proto.ProtoTagAbridged)
		isIntermediate := bytes.Equal(protoTag, proto.ProtoTagIntermediate)
		isSecure := bytes.Equal(protoTag, proto.ProtoTagSecure)

		if !isAbridged && !isIntermediate && !isSecure {
			continue
		}

		if isSecure {
			if isTLS && !cfg.Modes.TLS {
				continue
			}
			if !isTLS && !cfg.Modes.Secure {
				continue
			}
		} else {
			if !cfg.Modes.Classic {
				continue
			}
		}

		dcIdx := int(int16(binary.LittleEndian.Uint16(decrypted[config.DCIdxPos : config.DCIdxPos+2])))

		if cfg.ReplayCheckLen > 0 {
			UsedHandshakes.Add(decPrekeyAndIV)
		}

		encIV16b := make([]byte, 16)
		copy(encIV16b, encIV)
		streamEncryptor := crypto.NewAESCTR(encKey, crypto.Uint128FromBytes(encIV16b))
		cryptoR := &proto.CryptoReader{Upstream: sr, Decryptor: streamDecryptorTmp, BlockSize: 1}
		cryptoW := &proto.CryptoWriter{Upstream: sw, Encryptor: streamEncryptor, BlockSize: 1}

		return &HandshakeResult{
			Reader:    cryptoR,
			Writer:    cryptoW,
			ProtoTag:  protoTag,
			SecretHex: fmt.Sprintf("%x", secret),
			DcIdx:     dcIdx,
			EncKeyIV:  append(encKey, encIV...),
			Peer:      conn.RemoteAddr(),
		}, nil, nil
	}

	return nil, handshake, fmt.Errorf("no matching secret")
}

func ReverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}
