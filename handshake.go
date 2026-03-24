package main

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
)

// ── Replay 防护 ───────────────────────────────────────────────────────────────

type replayCache struct {
	mu    sync.Mutex
	cache map[string]bool
	order []string
	maxLen int
}

func newReplayCache(maxLen int) *replayCache {
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

var usedHandshakes *replayCache
var clientIPs *replayCache

// ── 握手结果 ──────────────────────────────────────────────────────────────────

type handshakeResult struct {
	reader    streamReader
	writer    streamWriter
	protoTag  []byte
	secretHex string
	dcIdx     int
	encKeyIV  []byte
	peer      net.Addr
}

// ── TLS 伪装握手 ──────────────────────────────────────────────────────────────

func handleFakeTLSHandshake(handshake []byte, reader streamReader, writer streamWriter,
	peer net.Addr, cfg *Config) (streamReader, streamWriter, error) {

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
	tlsExtensions = append(tlsExtensions, globalRand.GenX25519PublicKey()...)
	tlsExtensions = append(tlsExtensions, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)

	digest := handshake[digestPos : digestPos+digestLen]

	if usedHandshakes.Has(digest[:digestHalfLen]) {
		return nil, nil, fmt.Errorf("duplicate handshake")
	}

	sessIDLen := int(handshake[sessionIDLenPos])
	sessID := handshake[sessionIDPos : sessionIDPos+sessIDLen]

	dbgf(cfg, "[DEBUG] TLS handshake: handshake len=%d digestPos=%d digest=%x\n",
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

		dbgf(cfg, "[DEBUG] TLS xored[:4]=%x (want 00000000)\n", xored[:4])

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
		dbgf(cfg, "[DEBUG] TLS timestamp=%d now=%d skew=%d ok=%v\n", timestamp, now, skew, clientTimeOK)
		if !clientTimeOK && !cfg.IgnoreTimeSkew && !clientTimeSmall {
			continue
		}

		fakeCertLen := rand.Intn(4096-1024) + 1024
		httpData := globalRand.Bytes(fakeCertLen)

		srvHello := append(tlsVers, make([]byte, digestLen)...)
		srvHello = append(srvHello, byte(sessIDLen))
		srvHello = append(srvHello, sessID...)
		srvHello = append(srvHello, tlsCiphersuite...)
		srvHello = append(srvHello, 0x00)
		srvHello = append(srvHello, tlsExtensions...)

		// TLS Record:  + version(2) + length(2) +  + length(3) + srvHello
		// 对应 Python: b"" + TLS_VERS + int.to_bytes(len(srv_hello)+4, 2, "big")
		//              + b"" + int.to_bytes(len(srv_hello), 3, "big") + srv_hello
		srvHelloInnerLen := make([]byte, 3)
		srvHelloInnerLen[0] = byte(len(srvHello) >> 16)
		srvHelloInnerLen[1] = byte(len(srvHello) >> 8)
		srvHelloInnerLen[2] = byte(len(srvHello))
		outerLen := len(srvHello) + 4 // 4 = 1() + 3(inner len)
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
			usedHandshakes.Add(digest[:digestHalfLen])
		}

		return &fakeTLSReader{upstream: reader}, &fakeTLSWriter{upstream: writer}, nil
	}

	return nil, nil, fmt.Errorf("no matching secret")
}

func appendUint24(b []byte, v int) []byte {
	return append(b, byte(v>>16), byte(v>>8), byte(v))
}

// ── 主握手处理 ────────────────────────────────────────────────────────────────

func handleHandshake(conn net.Conn, cfg *Config) (*handshakeResult, []byte, error) {
	tlsStartBytes := []byte{0x16, 0x03, 0x01}

	reader := &tcpReader{conn: conn}
	writer := &tcpWriter{conn: conn}

	// proxy protocol 解析
	var peerAddr net.Addr = conn.RemoteAddr()
	if cfg.ProxyProtocol {
		var err2 error
		peerAddr, err2 = handleProxyProtocol(reader, peerAddr)
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

	var sr streamReader = reader
	var sw streamWriter = writer

	if isTLS {
		newReader, newWriter, err := handleFakeTLSHandshake(handshake, sr, sw, conn.RemoteAddr(), cfg)
		if err != nil {
			return nil, handshake, fmt.Errorf("tls handshake failed: %w", err)
		}
		sr = newReader
		sw = newWriter
		hs, err := sr.ReadExactly(HandshakeLen)
		if err != nil {
			return nil, nil, err
		}
		handshake = hs
	} else {
		if !cfg.Modes.Classic && !cfg.Modes.Secure {
			return nil, handshake, fmt.Errorf("classic/secure modes disabled")
		}
		rest, err := sr.ReadExactly(HandshakeLen - len(handshake))
		if err != nil {
			return nil, nil, err
		}
		handshake = append(handshake, rest...)
	}

	decPrekeyAndIV := handshake[SkipLen : SkipLen+PrekeyLen+IVLen]
	decPrekey := decPrekeyAndIV[:PrekeyLen]
	decIV := decPrekeyAndIV[PrekeyLen:]

	encPrekeyAndIV := make([]byte, len(decPrekeyAndIV))
	copy(encPrekeyAndIV, decPrekeyAndIV)
	reverseBytes(encPrekeyAndIV)
	encPrekey := encPrekeyAndIV[:PrekeyLen]
	encIV := encPrekeyAndIV[PrekeyLen:]

	if cfg.ReplayCheckLen > 0 && usedHandshakes.Has(decPrekeyAndIV) {
		return nil, handshake, fmt.Errorf("replay detected")
	}

	for _, secret := range cfg.Secrets {
		// 派生解密 key/iv（用独立 slice 避免 append 污染底层数组）
		decInput := make([]byte, len(decPrekey)+len(secret))
		copy(decInput, decPrekey)
		copy(decInput[len(decPrekey):], secret)
		decKeyRaw := sha256.Sum256(decInput)
		decKey := decKeyRaw[:]
		decIV16 := make([]byte, 16)
		copy(decIV16, decIV)

		// 派生加密 key/iv
		encInput := make([]byte, len(encPrekey)+len(secret))
		copy(encInput, encPrekey)
		copy(encInput[len(encPrekey):], secret)
		encKeyRaw := sha256.Sum256(encInput)
		encKey := encKeyRaw[:]
		encIV16 := make([]byte, 16)
		copy(encIV16, encIV)

		// 解密 handshake 做验证，同一个实例继续用于数据流（CTR状态连续）
		streamDecryptorTmp := newAESCTR(decKey, uint128FromBytes(decIV16))
		decrypted := streamDecryptorTmp.decrypt(handshake)

		protoTag := decrypted[ProtoTagPos : ProtoTagPos+4]

		isAbridged := bytes.Equal(protoTag, ProtoTagAbridged)
		isIntermediate := bytes.Equal(protoTag, ProtoTagIntermediate)
		isSecure := bytes.Equal(protoTag, ProtoTagSecure)

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

		dcIdx := int(int16(binary.LittleEndian.Uint16(decrypted[DCIdxPos : DCIdxPos+2])))

		if cfg.ReplayCheckLen > 0 {
			usedHandshakes.Add(decPrekeyAndIV)
		}

		// streamDecryptorTmp 已消耗了 handshake 的 CTR 状态，直接复用作为数据流解密器
		// encryptor 从头开始（客户端发来数据时 proxy->client 方向加密）
		encIV16b := make([]byte, 16)
		copy(encIV16b, encIV)
		streamEncryptor := newAESCTR(encKey, uint128FromBytes(encIV16b))
		cryptoR := &cryptoReader{upstream: sr, decryptor: streamDecryptorTmp, blockSize: 1}
		cryptoW := &cryptoWriter{upstream: sw, encryptor: streamEncryptor, blockSize: 1}

		return &handshakeResult{
			reader:    cryptoR,
			writer:    cryptoW,
			protoTag:  protoTag,
			secretHex: fmt.Sprintf("%x", secret),
			dcIdx:     dcIdx,
			encKeyIV:  append(encKey, encIV...),
			peer:      conn.RemoteAddr(),
		}, nil, nil
	}

	return nil, handshake, fmt.Errorf("no matching secret")
}

func reverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}