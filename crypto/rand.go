package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"sync"
)

// CryptoRand 是线程安全的加密级随机数生成器（CSPRNG）。
// 实现：用系统熵初始化 AES-CTR 流，后续随机数直接由 AES-CTR 生成，
// 无需每次调用都向 OS 申请随机数，兼顾安全性与性能。
type CryptoRand struct {
	mu  sync.Mutex
	ctr *AESCTR
	buf []byte
}

func NewCryptoRand() *CryptoRand {
	key := make([]byte, 32)
	rand.Read(key)
	ivBytes := make([]byte, 16)
	rand.Read(ivBytes)
	iv := Uint128FromBytes(ivBytes)
	return &CryptoRand{
		ctr: NewAESCTR(key, iv),
	}
}

// Bytes 返回 n 个密码学安全的随机字节。
// 修复：直接用全零明文驱动 AES-CTR（计数器模式天然是 CSPRNG），
// 不再每次向 OS 申请随机数再加密，减少系统调用，提升高并发下的性能。
func (r *CryptoRand) Bytes(n int) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	const chunkSize = 512
	for len(r.buf) < n {
		// AES-CTR 以全零明文生成随机流，等价于直接输出密钥流
		plain := make([]byte, chunkSize)
		r.buf = append(r.buf, r.ctr.Encrypt(plain)...)
	}
	out := make([]byte, n)
	copy(out, r.buf[:n])
	r.buf = r.buf[n:]
	return out
}

// Intn 返回 [0, n) 范围内的密码学安全随机整数。
func (r *CryptoRand) Intn(n int) int {
	b := r.Bytes(8)
	val := binary.BigEndian.Uint64(b)
	return int(val % uint64(n))
}

func (r *CryptoRand) Choice(s []string) string {
	return s[r.Intn(len(s))]
}

// GenX25519PublicKey 生成一个模 P 有平方根的随机数（用于 TLS 伪装中的 key_share）。
func (r *CryptoRand) GenX25519PublicKey() []byte {
	P := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	nBytes := r.Bytes(32)
	n := new(big.Int).SetBytes(nBytes)
	n.Mod(n, P)
	result := new(big.Int).Mul(n, n)
	result.Mod(result, P)
	out := make([]byte, 32)
	resultBytes := result.Bytes()
	copy(out[32-len(resultBytes):], resultBytes)
	// X25519 使用小端序
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// GlobalRand 全局加密随机数生成器实例。
var GlobalRand = NewCryptoRand()

// RandHex 生成 n 个随机十六进制字符。
// 修复：改用 GlobalRand（AES-CTR CSPRNG）替代 math/rand，保持全局随机源一致。
func RandHex(n int) string {
	const chars = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[GlobalRand.Intn(16)]
	}
	return string(b)
}
