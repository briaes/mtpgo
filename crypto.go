package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

// AES-CTR 加解密器
type aesCTR struct {
	stream cipher.Stream
}

func newAESCTR(key []byte, iv uint128) *aesCTR {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ivBytes := make([]byte, 16)
	binary.BigEndian.PutUint64(ivBytes[:8], iv.hi)
	binary.BigEndian.PutUint64(ivBytes[8:], iv.lo)
	stream := cipher.NewCTR(block, ivBytes)
	return &aesCTR{stream: stream}
}

func (c *aesCTR) encrypt(data []byte) []byte {
	out := make([]byte, len(data))
	c.stream.XORKeyStream(out, data)
	return out
}

func (c *aesCTR) decrypt(data []byte) []byte {
	return c.encrypt(data) // CTR 模式加解密相同
}

// AES-CBC 加解密器（用于中间代理握手）
type aesCBC struct {
	encBlock cipher.Block
	decBlock cipher.Block
	iv       []byte
}

func newAESCBC(key, iv []byte) *aesCBC {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	block2, _ := aes.NewCipher(key)
	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)
	return &aesCBC{encBlock: block, decBlock: block2, iv: ivCopy}
}

func (c *aesCBC) encrypt(data []byte) []byte {
	out := make([]byte, len(data))
	enc := cipher.NewCBCEncrypter(c.encBlock, c.iv)
	enc.CryptBlocks(out, data)
	copy(c.iv, out[len(out)-16:])
	return out
}

func (c *aesCBC) decrypt(data []byte) []byte {
	out := make([]byte, len(data))
	dec := cipher.NewCBCDecrypter(c.decBlock, c.iv)
	dec.CryptBlocks(out, data)
	copy(c.iv, data[len(data)-16:])
	return out
}

// uint128 用于 CTR 模式 IV
type uint128 struct {
	hi, lo uint64
}

func uint128FromBytes(b []byte) uint128 {
	return uint128{
		hi: binary.BigEndian.Uint64(b[:8]),
		lo: binary.BigEndian.Uint64(b[8:]),
	}
}
