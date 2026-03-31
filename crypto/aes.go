package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

// Cipher 是加解密器的通用接口
type Cipher interface {
	Encrypt([]byte) []byte
	Decrypt([]byte) []byte
}

// ── AES-CTR ───────────────────────────────────────────────────────────────────

type AESCTR struct {
	stream cipher.Stream
}

func NewAESCTR(key []byte, iv Uint128) *AESCTR {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ivBytes := make([]byte, 16)
	binary.BigEndian.PutUint64(ivBytes[:8], iv.Hi)
	binary.BigEndian.PutUint64(ivBytes[8:], iv.Lo)
	stream := cipher.NewCTR(block, ivBytes)
	return &AESCTR{stream: stream}
}

func (c *AESCTR) Encrypt(data []byte) []byte {
	out := make([]byte, len(data))
	c.stream.XORKeyStream(out, data)
	return out
}

func (c *AESCTR) Decrypt(data []byte) []byte {
	return c.Encrypt(data) // CTR 模式加解密相同
}

// ── AES-CBC ───────────────────────────────────────────────────────────────────

type AESCBC struct {
	encBlock cipher.Block
	decBlock cipher.Block
	iv       []byte
}

func NewAESCBC(key, iv []byte) *AESCBC {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	block2, _ := aes.NewCipher(key)
	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)
	return &AESCBC{encBlock: block, decBlock: block2, iv: ivCopy}
}

func (c *AESCBC) Encrypt(data []byte) []byte {
	out := make([]byte, len(data))
	enc := cipher.NewCBCEncrypter(c.encBlock, c.iv)
	enc.CryptBlocks(out, data)
	copy(c.iv, out[len(out)-16:])
	return out
}

func (c *AESCBC) Decrypt(data []byte) []byte {
	out := make([]byte, len(data))
	dec := cipher.NewCBCDecrypter(c.decBlock, c.iv)
	dec.CryptBlocks(out, data)
	copy(c.iv, data[len(data)-16:])
	return out
}

// ── Uint128 ───────────────────────────────────────────────────────────────────

type Uint128 struct {
	Hi, Lo uint64
}

func Uint128FromBytes(b []byte) Uint128 {
	return Uint128{
		Hi: binary.BigEndian.Uint64(b[:8]),
		Lo: binary.BigEndian.Uint64(b[8:]),
	}
}
