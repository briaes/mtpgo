package proxy

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"mtproxy/config"
	"mtproxy/crypto"
	"mtproxy/proto"
)

// ── IP 信息 ───────────────────────────────────────────────────────────────────

type IPInfo struct {
	mu   sync.RWMutex
	IPv4 string
	IPv6 string
}

var MyIPInfo = &IPInfo{}

func (i *IPInfo) Set(v4, v6 string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.IPv4 = v4
	i.IPv6 = v6
}

func (i *IPInfo) Get() (string, string) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.IPv4, i.IPv6
}

// ── 常量 ──────────────────────────────────────────────────────────────────────

const MinCertLen = 1024

const TGDatacenterPort = 443

var TGDatacentersV4 = []string{
	"149.154.175.50", "149.154.167.51", "149.154.175.100",
	"149.154.167.91", "149.154.171.5",
}

var TGDatacentersV6 = []string{
	"2001:b28:f23d:f001::a", "2001:67c:04e8:f002::a", "2001:b28:f23d:f003::a",
	"2001:67c:04e8:f004::a", "2001:b28:f23f:f005::a",
}

// 运行时会更新
var TGMiddleProxiesV4 = map[int][][2]interface{}{
	1: {{"149.154.175.50", 8888}}, -1: {{"149.154.175.50", 8888}},
	2: {{"149.154.161.144", 8888}}, -2: {{"149.154.161.144", 8888}},
	3: {{"149.154.175.100", 8888}}, -3: {{"149.154.175.100", 8888}},
	4: {{"91.108.4.136", 8888}}, -4: {{"149.154.165.109", 8888}},
	5: {{"91.108.56.183", 8888}}, -5: {{"91.108.56.183", 8888}},
}

var TGMiddleProxiesV6 = map[int][][2]interface{}{
	1: {{"2001:b28:f23d:f001::d", 8888}}, -1: {{"2001:b28:f23d:f001::d", 8888}},
	2: {{"2001:67c:04e8:f002::d", 80}}, -2: {{"2001:67c:04e8:f002::d", 80}},
	3: {{"2001:b28:f23d:f003::d", 8888}}, -3: {{"2001:b28:f23d:f003::d", 8888}},
	4: {{"2001:67c:04e8:f004::d", 8888}}, -4: {{"2001:67c:04e8:f004::d", 8888}},
	5: {{"2001:b28:f23f:f005::d", 8888}}, -5: {{"2001:b28:f23f:f005::d", 8888}},
}

var proxySecretHex = "c4f9faca9678e6bb48ad6c7e2ce5c0d24430645d554addeb55419e034da62721" +
	"d046eaab6e52ab14a95a443ecfb3463e79a05a66612adf9caeda8be9a80da698" +
	"6fb0a6ff387af84d88ef3a6413713e5c3377f6e1a3d47d99f5e0c56eece8f05c" +
	"54c490b079e31bef82ff0ee8f2b0a32756d249c5f21269816cb7061b265db212"

var ProxySecret, _ = hex.DecodeString(proxySecretHex)

var MiddleProxyMu sync.RWMutex

// ── 中间代理握手 ──────────────────────────────────────────────────────────────

func getMiddleproxyAESKeyIV(nonceSrv, nonceClt, cltTS, srvIP, cltPort, purpose,
	cltIP, srvPort, middleproxySecret []byte,
	cltIPv6, srvIPv6 []byte) ([]byte, []byte) {

	emptyIP := []byte{0, 0, 0, 0}
	if len(cltIP) == 0 || len(srvIP) == 0 {
		cltIP = emptyIP
		srvIP = emptyIP
	}

	s := make([]byte, 0, 256)
	s = append(s, nonceSrv...)
	s = append(s, nonceClt...)
	s = append(s, cltTS...)
	s = append(s, srvIP...)
	s = append(s, cltPort...)
	s = append(s, purpose...)
	s = append(s, cltIP...)
	s = append(s, srvPort...)
	s = append(s, middleproxySecret...)
	s = append(s, nonceSrv...)

	if len(cltIPv6) > 0 && len(srvIPv6) > 0 {
		s = append(s, cltIPv6...)
		s = append(s, srvIPv6...)
	}
	s = append(s, nonceClt...)

	md5sum := md5.Sum(s[1:])
	sha1sum := sha1.Sum(s)

	key := append(md5sum[:12], sha1sum[:]...)
	iv := md5.Sum(s[2:])
	return key, iv[:]
}

func middleproxyHandshake(conn net.Conn) (proto.StreamReader, proto.StreamWriter, string, int, error) {
	const startSeqNo = -2
	const nonceLen = 16

	rpcHandshake := []byte{0xf5, 0xee, 0x82, 0x76}
	rpcNonce := []byte{0xaa, 0x87, 0xcb, 0x7a}
	rpcFlags := []byte{0x00, 0x00, 0x00, 0x00}
	cryptoAES := []byte{0x01, 0x00, 0x00, 0x00}

	r := &proto.TCPReader{Conn: conn}
	w := &proto.TCPWriter{Conn: conn}

	frameW := &proto.MtprotoFrameWriter{Upstream: w, SeqNo: startSeqNo}

	keySelector := ProxySecret[:4]
	cryptoTS := make([]byte, 4)
	binary.LittleEndian.PutUint32(cryptoTS, uint32(time.Now().Unix()))

	nonce := crypto.GlobalRand.Bytes(nonceLen)

	msg := append(append(append(append(rpcNonce, keySelector...), cryptoAES...), cryptoTS...), nonce...)
	if err := frameW.Write(msg, nil); err != nil {
		return nil, nil, "", 0, err
	}

	frameR := &proto.MtprotoFrameReader{Upstream: r, SeqNo: startSeqNo}
	ans, _, err := frameR.Read(1024)
	if err != nil || len(ans) != 32 {
		return nil, nil, "", 0, fmt.Errorf("bad rpc answer")
	}

	rpcType := ans[:4]
	rpcKeySelector := ans[4:8]
	rpcSchema := ans[8:12]
	rpcNonceAns := ans[16:32]

	if !bytes.Equal(rpcType, rpcNonce) || !bytes.Equal(rpcKeySelector, keySelector) || !bytes.Equal(rpcSchema, cryptoAES) {
		return nil, nil, "", 0, fmt.Errorf("bad rpc nonce answer")
	}

	localAddr := conn.LocalAddr().(*net.TCPAddr)
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)

	tgIP := remoteAddr.IP
	myIP := localAddr.IP
	tgPort := remoteAddr.Port
	myPort := localAddr.Port

	tgPortBytes := make([]byte, 2)
	myPortBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(tgPortBytes, uint16(tgPort))
	binary.LittleEndian.PutUint16(myPortBytes, uint16(myPort))

	ipv4, ipv6 := MyIPInfo.Get()

	var tgIPBytes, myIPBytes, tgIPv6Bytes, myIPv6Bytes []byte
	useIPv6 := tgIP.To4() == nil

	if !useIPv6 {
		if ipv4 != "" {
			myIP = net.ParseIP(ipv4).To4()
		}
		tgIPBytes = reverseIP(tgIP.To4())
		myIPBytes = reverseIP(myIP.To4())
	} else {
		if ipv6 != "" {
			myIP = net.ParseIP(ipv6)
		}
		tgIPv6Bytes = tgIP.To16()
		myIPv6Bytes = myIP.To16()
	}

	encKey, encIV := getMiddleproxyAESKeyIV(rpcNonceAns, nonce, cryptoTS, tgIPBytes, myPortBytes,
		[]byte("CLIENT"), myIPBytes, tgPortBytes, ProxySecret, myIPv6Bytes, tgIPv6Bytes)
	decKey, decIV := getMiddleproxyAESKeyIV(rpcNonceAns, nonce, cryptoTS, tgIPBytes, myPortBytes,
		[]byte("SERVER"), myIPBytes, tgPortBytes, ProxySecret, myIPv6Bytes, tgIPv6Bytes)

	encryptor := crypto.NewAESCBC(encKey, encIV)
	decryptor := crypto.NewAESCBC(decKey, decIV)

	senderPID := []byte("IPIPPRPDTIME")
	peerPID := []byte("IPIPPRPDTIME")
	handshakeMsg := append(append(append(rpcHandshake, rpcFlags...), senderPID...), peerPID...)

	frameW.Upstream = &proto.CryptoWriter{Upstream: w, Encryptor: encryptor, BlockSize: 16}
	if err := frameW.Write(handshakeMsg, nil); err != nil {
		return nil, nil, "", 0, err
	}

	frameR.Upstream = &proto.CryptoReader{Upstream: r, Decryptor: decryptor, BlockSize: 16}
	hsAns, _, err := frameR.Read(1024)
	if err != nil || len(hsAns) != 32 {
		return nil, nil, "", 0, fmt.Errorf("bad rpc handshake answer")
	}
	hsType := hsAns[:4]
	hsPeerPID := hsAns[20:32]
	if !bytes.Equal(hsType, rpcHandshake) || !bytes.Equal(hsPeerPID, senderPID) {
		return nil, nil, "", 0, fmt.Errorf("bad rpc handshake answer content")
	}

	myIPStr := myIP.String()
	return frameR, frameW, myIPStr, myPort, nil
}

func reverseIP(ip []byte) []byte {
	out := make([]byte, len(ip))
	for i, b := range ip {
		out[len(ip)-1-i] = b
	}
	return out
}

// ── 直连 TG ───────────────────────────────────────────────────────────────────

var reservedNonceFirstChars = []byte{0xef}
var reservedNonceBeginnings = [][]byte{
	{0x48, 0x45, 0x41, 0x44}, {0x50, 0x4F, 0x53, 0x54},
	{0x47, 0x45, 0x54, 0x20}, {0xee, 0xee, 0xee, 0xee},
	{0xdd, 0xdd, 0xdd, 0xdd}, {0x16, 0x03, 0x01, 0x02},
}
var reservedNonceContinues = [][]byte{{0x00, 0x00, 0x00, 0x00}}

func DoDirectHandshake(protoTag []byte, dcIdx int, decKeyAndIV []byte, cfg *config.Config) (proto.StreamReader, proto.StreamWriter, error) {
	if dcIdx < 0 {
		dcIdx = -dcIdx
	}
	dcIdx--

	ipv4, ipv6 := MyIPInfo.Get()
	var dc string
	if ipv6 != "" && (cfg.PreferIPv6 || ipv4 == "") {
		if dcIdx < 0 || dcIdx >= len(TGDatacentersV6) {
			return nil, nil, fmt.Errorf("invalid dc_idx %d for v6", dcIdx)
		}
		dc = TGDatacentersV6[dcIdx]
	} else {
		if dcIdx < 0 || dcIdx >= len(TGDatacentersV4) {
			return nil, nil, fmt.Errorf("invalid dc_idx %d for v4", dcIdx)
		}
		dc = TGDatacentersV4[dcIdx]
	}

	addr := net.JoinHostPort(dc, fmt.Sprintf("%d", TGDatacenterPort))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to dc %s: %w", addr, err)
	}

	// 生成随机 nonce
	var rnd []byte
	for {
		rnd = crypto.GlobalRand.Bytes(config.HandshakeLen)
		if bytes.IndexByte(reservedNonceFirstChars, rnd[0]) >= 0 {
			continue
		}
		bad := false
		for _, b := range reservedNonceBeginnings {
			if bytes.Equal(rnd[:4], b) {
				bad = true
				break
			}
		}
		if bad {
			continue
		}
		for _, b := range reservedNonceContinues {
			if bytes.Equal(rnd[4:8], b) {
				bad = true
				break
			}
		}
		if !bad {
			break
		}
	}

	copy(rnd[config.ProtoTagPos:], protoTag)

	if decKeyAndIV != nil {
		reversed := make([]byte, len(decKeyAndIV))
		copy(reversed, decKeyAndIV)
		ReverseBytes(reversed)
		copy(rnd[config.SkipLen:], reversed[:config.KeyLen+config.IVLen])
	}

	// dec: reversed slice of rnd[SKIP:SKIP+KEY+IV]
	decKIV := make([]byte, config.KeyLen+config.IVLen)
	copy(decKIV, rnd[config.SkipLen:config.SkipLen+config.KeyLen+config.IVLen])
	ReverseBytes(decKIV)
	decKey := make([]byte, config.KeyLen)
	copy(decKey, decKIV[:config.KeyLen])
	decIV16 := make([]byte, 16)
	copy(decIV16, decKIV[config.KeyLen:config.KeyLen+config.IVLen])
	decryptor := crypto.NewAESCTR(decKey, crypto.Uint128FromBytes(decIV16))

	// enc: forward slice of rnd[SKIP:SKIP+KEY+IV]
	encKey := make([]byte, config.KeyLen)
	copy(encKey, rnd[config.SkipLen:config.SkipLen+config.KeyLen])
	encIV16 := make([]byte, 16)
	copy(encIV16, rnd[config.SkipLen+config.KeyLen:config.SkipLen+config.KeyLen+config.IVLen])
	encryptor := crypto.NewAESCTR(encKey, crypto.Uint128FromBytes(encIV16))

	rndEnc := make([]byte, len(rnd))
	copy(rndEnc, rnd[:config.ProtoTagPos])
	// encryptor 加密整个 rnd，取 ProtoTagPos 之后的部分
	encryptedRnd := encryptor.Encrypt(rnd)
	copy(rndEnc[config.ProtoTagPos:], encryptedRnd[config.ProtoTagPos:])

	if _, err := conn.Write(rndEnc); err != nil {
		conn.Close()
		return nil, nil, err
	}

	r := &proto.TCPReader{Conn: conn}
	w := &proto.TCPWriter{Conn: conn}
	return &proto.CryptoReader{Upstream: r, Decryptor: decryptor, BlockSize: 1},
		&proto.CryptoWriter{Upstream: w, Encryptor: encryptor, BlockSize: 1}, nil
}

// ── 中间代理出站 ──────────────────────────────────────────────────────────────
func DoMiddleproxyHandshake(protoTag []byte, dcIdx int, clIP string, clPort int, cfg *config.Config) (proto.StreamReader, proto.StreamWriter, error) {
    ipv4, ipv6 := MyIPInfo.Get()
    useIPv6 := ipv6 != "" && (cfg.PreferIPv6 || ipv4 == "")

    var proxies [][2]interface{}
    if useIPv6 {
        p, ok := TGMiddleProxiesV6[dcIdx]
        if !ok {
            return nil, nil, fmt.Errorf("no v6 proxy for dc %d", dcIdx)
        }
        proxies = p
    } else {
        p, ok := TGMiddleProxiesV4[dcIdx]
        if !ok {
            return nil, nil, fmt.Errorf("no v4 proxy for dc %d", dcIdx)
        }
        proxies = p
    }

    chosen := proxies[crypto.GlobalRand.Intn(len(proxies))]
    host := chosen[0].(string)
    port := chosen[1].(int)

    conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), 10*time.Second)
    if err != nil {
        return nil, nil, err
    }

    frameR, frameW, myIP, myPort, err := middleproxyHandshake(conn)
    if err != nil {
        conn.Close()
        return nil, nil, err
    }

    proxyR := &proxyReqReader{upstream: frameR}
    proxyW := newProxyReqWriter(frameW, clIP, clPort, myIP, myPort, protoTag, cfg)

    return proxyR, proxyW, nil
}

// ── ProxyReq 流（包装中间代理协议）────────────────────────────────────────────

type proxyReqReader struct{ upstream proto.StreamReader }

func (r *proxyReqReader) ReadExactly(n int) ([]byte, error) {
	data, _, err := r.Read(n)
	return data, err
}

func (r *proxyReqReader) Read(bufSize int) ([]byte, map[string]bool, error) {
	rpcProxyAns := []byte{0x0d, 0xda, 0x03, 0x44}
	rpcCloseExt := []byte{0xa2, 0x34, 0xb6, 0x5e}
	rpcSimpleAck := []byte{0x9b, 0x40, 0xac, 0x3b}
	rpcUnknown := []byte{0xdf, 0xa2, 0x30, 0x57}

	data, _, err := r.upstream.Read(bufSize)
	if err != nil || len(data) < 4 {
		return nil, nil, err
	}
	ansType := data[:4]
	if bytes.Equal(ansType, rpcCloseExt) {
		return nil, nil, fmt.Errorf("remote closed")
	}
	if bytes.Equal(ansType, rpcProxyAns) {
		return data[16:], nil, nil
	}
	if bytes.Equal(ansType, rpcSimpleAck) {
		return data[12:16], map[string]bool{"SIMPLE_ACK": true}, nil
	}
	if bytes.Equal(ansType, rpcUnknown) {
		return nil, map[string]bool{"SKIP_SEND": true}, nil
	}
	return nil, map[string]bool{"SKIP_SEND": true}, nil
}

type proxyReqWriter struct {
	upstream     proto.StreamWriter
	remoteIPPort []byte
	ourIPPort    []byte
	outConnID    []byte
	protoTag     []byte
	adTag        []byte
}

func newProxyReqWriter(upstream proto.StreamWriter, clIP string, clPort int,
	myIP string, myPort int, protoTag []byte, cfg *config.Config) *proxyReqWriter {

	remote := encodeIPPort(clIP, clPort)
	our := encodeIPPort(myIP, myPort)

	return &proxyReqWriter{
		upstream:     upstream,
		remoteIPPort: remote,
		ourIPPort:    our,
		outConnID:    crypto.GlobalRand.Bytes(8),
		protoTag:     protoTag,
		adTag:        cfg.ADTag,
	}
}

func encodeIPPort(ip string, port int) []byte {
	parsed := net.ParseIP(ip)
	portBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(portBytes, uint32(port))

	if parsed.To4() != nil {
		out := make([]byte, 10, 20)
		out = append(out, 0xff, 0xff)
		out = append(out, parsed.To4()...)
		out = append(out, portBytes...)
		return out
	}
	out := parsed.To16()
	return append(out, portBytes...)
}

func (w *proxyReqWriter) Write(msg []byte, extra map[string]bool) error {
	rpcProxyReq := []byte{0xee, 0xf1, 0xce, 0x36}
	extraSize := []byte{0x18, 0x00, 0x00, 0x00}
	proxyTag := []byte{0xae, 0x26, 0x1e, 0xdb}
	fourBytesAligner := []byte{0x00, 0x00, 0x00}

	const (
		flagHasADTag     = 0x8
		flagMagic        = 0x1000
		flagExtmode2     = 0x20000
		flagPad          = 0x8000000
		flagIntermediate = 0x20000000
		flagAbridged     = 0x40000000
		flagQuickAck     = 0x80000000
	)

	flags := uint32(flagHasADTag | flagMagic | flagExtmode2)

	if bytes.Equal(w.protoTag, proto.ProtoTagAbridged) {
		flags |= flagAbridged
	} else if bytes.Equal(w.protoTag, proto.ProtoTagIntermediate) {
		flags |= flagIntermediate
	} else if bytes.Equal(w.protoTag, proto.ProtoTagSecure) {
		flags |= flagIntermediate | flagPad
	}

	if extra != nil && extra["QUICKACK_FLAG"] {
		flags |= flagQuickAck
	}

	flagsBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(flagsBytes, flags)

	full := append(rpcProxyReq, flagsBytes...)
	full = append(full, w.outConnID...)
	full = append(full, w.remoteIPPort...)
	full = append(full, w.ourIPPort...)
	full = append(full, extraSize...)
	full = append(full, proxyTag...)
	full = append(full, byte(len(w.adTag)))
	full = append(full, w.adTag...)
	full = append(full, fourBytesAligner...)
	full = append(full, msg...)

	return w.upstream.Write(full, extra)
}

func (w *proxyReqWriter) WriteEOF() error   { return w.upstream.WriteEOF() }
func (w *proxyReqWriter) Drain() error      { return w.upstream.Drain() }
func (w *proxyReqWriter) Close()            { w.upstream.Close() }
func (w *proxyReqWriter) Abort()            { w.upstream.Abort() }
func (w *proxyReqWriter) GetConn() net.Conn { return w.upstream.GetConn() }
