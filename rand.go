package main

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	mathrand "math/rand"
	"sync"
)

// cryptoRand 是线程安全的加密级随机数生成器
type cryptoRand struct {
	mu  sync.Mutex
	ctr *aesCTR
	buf []byte
}

func newCryptoRand() *cryptoRand {
	key := make([]byte, 32)
	rand.Read(key)
	ivBytes := make([]byte, 16)
	rand.Read(ivBytes)
	iv := uint128FromBytes(ivBytes)
	return &cryptoRand{
		ctr: newAESCTR(key, iv),
	}
}

func (r *cryptoRand) Bytes(n int) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	const chunkSize = 512
	for len(r.buf) < n {
		plain := make([]byte, chunkSize)
		rand.Read(plain)
		r.buf = append(r.buf, r.ctr.encrypt(plain)...)
	}
	out := make([]byte, n)
	copy(out, r.buf[:n])
	r.buf = r.buf[n:]
	return out
}

func (r *cryptoRand) Intn(n int) int {
	b := r.Bytes(8)
	val := binary.BigEndian.Uint64(b)
	return int(val % uint64(n))
}

func (r *cryptoRand) Choice(s []string) string {
	return s[r.Intn(len(s))]
}

// GenX25519PublicKey 生成一个模 P 有平方根的随机数（用于 TLS 伪装）
func (r *cryptoRand) GenX25519PublicKey() []byte {
	P := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	nBytes := r.Bytes(32)
	n := new(big.Int).SetBytes(nBytes)
	n.Mod(n, P)
	result := new(big.Int).Mul(n, n)
	result.Mod(result, P)
	out := make([]byte, 32)
	resultBytes := result.Bytes()
	copy(out[32-len(resultBytes):], resultBytes)
	// little-endian
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

var globalRand = newCryptoRand()

// randHex 生成 n 个随机十六进制字符
func randHex(n int) string {
	const chars = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[mathrand.Intn(16)]
	}
	return string(b)
}
