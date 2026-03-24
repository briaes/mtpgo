package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// ── IP 信息 ───────────────────────────────────────────────────────────────────

type IPInfo struct {
	mu   sync.RWMutex
	IPv4 string
	IPv6 string
}

var myIPInfo = &IPInfo{}

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

// ── 直连 TG ───────────────────────────────────────────────────────────────────

var reservedNonceFirstChars = []byte{0xef}
var reservedNonceBeginnings = [][]byte{
	{0x48, 0x45, 0x41, 0x44}, {0x50, 0x4F, 0x53, 0x54},
	{0x47, 0x45, 0x54, 0x20}, {0xee, 0xee, 0xee, 0xee},
	{0xdd, 0xdd, 0xdd, 0xdd}, {0x16, 0x03, 0x01, 0x02},
}
var reservedNonceContinues = [][]byte{{0x00, 0x00, 0x00, 0x00}}

func doDirectHandshake(protoTag []byte, dcIdx int, decKeyAndIV []byte, cfg *Config) (streamReader, streamWriter, error) {
	if dcIdx < 0 {
		dcIdx = -dcIdx
	}
	dcIdx--

	ipv4, ipv6 := myIPInfo.Get()
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

	addr := fmt.Sprintf("%s:%d", dc, TGDatacenterPort)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to dc %s: %w", addr, err)
	}

	// 生成随机 nonce
	var rnd []byte
	for {
		rnd = globalRand.Bytes(HandshakeLen)
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

	copy(rnd[ProtoTagPos:], protoTag)

	if decKeyAndIV != nil {
		reversed := make([]byte, len(decKeyAndIV))
		copy(reversed, decKeyAndIV)
		reverseBytes(reversed)
		copy(rnd[SkipLen:], reversed[:KeyLen+IVLen])
	}

	// dec: reversed slice of rnd[SKIP:SKIP+KEY+IV]
	decKIV := make([]byte, KeyLen+IVLen)
	copy(decKIV, rnd[SkipLen:SkipLen+KeyLen+IVLen])
	reverseBytes(decKIV)
	decKey := make([]byte, KeyLen)
	copy(decKey, decKIV[:KeyLen])
	decIV16 := make([]byte, 16)
	copy(decIV16, decKIV[KeyLen:KeyLen+IVLen])
	decryptor := newAESCTR(decKey, uint128FromBytes(decIV16))

	// enc: forward slice of rnd[SKIP:SKIP+KEY+IV]
	encKey := make([]byte, KeyLen)
	copy(encKey, rnd[SkipLen:SkipLen+KeyLen])
	encIV16 := make([]byte, 16)
	copy(encIV16, rnd[SkipLen+KeyLen:SkipLen+KeyLen+IVLen])
	encryptor := newAESCTR(encKey, uint128FromBytes(encIV16))

	rndEnc := make([]byte, len(rnd))
	copy(rndEnc, rnd[:ProtoTagPos])
	// encryptor 加密整个 rnd，取 ProtoTagPos 之后的部分
	encryptedRnd := encryptor.encrypt(rnd)
	copy(rndEnc[ProtoTagPos:], encryptedRnd[ProtoTagPos:])

	if _, err := conn.Write(rndEnc); err != nil {
		conn.Close()
		return nil, nil, err
	}

	r := &tcpReader{conn: conn}
	w := &tcpWriter{conn: conn}
	return &cryptoReader{upstream: r, decryptor: decryptor, blockSize: 1},
		&cryptoWriter{upstream: w, encryptor: encryptor, blockSize: 1}, nil
}

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

func middleproxyHandshake(conn net.Conn) (streamReader, streamWriter, string, int, error) {
	const startSeqNo = -2
	const nonceLen = 16

	rpcHandshake := []byte{0xf5, 0xee, 0x82, 0x76}
	rpcNonce := []byte{0xaa, 0x87, 0xcb, 0x7a}
	rpcFlags := []byte{0x00, 0x00, 0x00, 0x00}
	cryptoAES := []byte{0x01, 0x00, 0x00, 0x00}

	r := &tcpReader{conn: conn}
	w := &tcpWriter{conn: conn}

	frameW := &mtprotoFrameWriter{upstream: w, seqNo: startSeqNo}

	keySelector := ProxySecret[:4]
	cryptoTS := make([]byte, 4)
	binary.LittleEndian.PutUint32(cryptoTS, uint32(time.Now().Unix()))

	nonce := globalRand.Bytes(nonceLen)

	msg := append(append(append(append(rpcNonce, keySelector...), cryptoAES...), cryptoTS...), nonce...)
	if err := frameW.Write(msg, nil); err != nil {
		return nil, nil, "", 0, err
	}

	frameR := &mtprotoFrameReader{upstream: r, seqNo: startSeqNo}
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

	ipv4, ipv6 := myIPInfo.Get()

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

	encryptor := newAESCBC(encKey, encIV)
	decryptor := newAESCBC(decKey, decIV)

	senderPID := []byte("IPIPPRPDTIME")
	peerPID := []byte("IPIPPRPDTIME")
	handshakeMsg := append(append(append(rpcHandshake, rpcFlags...), senderPID...), peerPID...)

	frameW.upstream = &cryptoWriter{upstream: w, encryptor: encryptor, blockSize: 16}
	if err := frameW.Write(handshakeMsg, nil); err != nil {
		return nil, nil, "", 0, err
	}

	frameR.upstream = &cryptoReader{upstream: r, decryptor: decryptor, blockSize: 16}
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

func doMiddleproxyHandshake(protoTag []byte, dcIdx int, clIP string, clPort int, cfg *Config) (streamReader, streamWriter, error) {
	ipv4, ipv6 := myIPInfo.Get()
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

	chosen := proxies[globalRand.Intn(len(proxies))]
	host := chosen[0].(string)
	port := chosen[1].(int)

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second)
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

type proxyReqReader struct{ upstream streamReader }

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
	upstream     streamWriter
	remoteIPPort []byte
	ourIPPort    []byte
	outConnID    []byte
	protoTag     []byte
	adTag        []byte
}

func newProxyReqWriter(upstream streamWriter, clIP string, clPort int,
	myIP string, myPort int, protoTag []byte, cfg *Config) *proxyReqWriter {

	remote := encodeIPPort(clIP, clPort)
	our := encodeIPPort(myIP, myPort)

	return &proxyReqWriter{
		upstream:     upstream,
		remoteIPPort: remote,
		ourIPPort:    our,
		outConnID:    globalRand.Bytes(8),
		protoTag:     protoTag,
		adTag:        cfg.ADTag,
	}
}

func encodeIPPort(ip string, port int) []byte {
	parsed := net.ParseIP(ip)
	portBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(portBytes, uint32(port))

	if parsed.To4() != nil {
		out := make([]byte, 10)
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
		flagHasADTag    = 0x8
		flagMagic       = 0x1000
		flagExtmode2    = 0x20000
		flagPad         = 0x8000000
		flagIntermediate = 0x20000000
		flagAbridged    = 0x40000000
		flagQuickAck    = 0x80000000
	)

	flags := uint32(flagHasADTag | flagMagic | flagExtmode2)

	if bytes.Equal(w.protoTag, ProtoTagAbridged) {
		flags |= flagAbridged
	} else if bytes.Equal(w.protoTag, ProtoTagIntermediate) {
		flags |= flagIntermediate
	} else if bytes.Equal(w.protoTag, ProtoTagSecure) {
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