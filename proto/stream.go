package proto

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"mtproxy/crypto"
)

// ── 基础接口 ──────────────────────────────────────────────────────────────────

type StreamReader interface {
	Read(n int) ([]byte, map[string]bool, error)
	ReadExactly(n int) ([]byte, error)
}

type StreamWriter interface {
	Write(data []byte, extra map[string]bool) error
	WriteEOF() error
	Drain() error
	Close()
	Abort()
	GetConn() net.Conn
}

// ── 基础 TCP 流 ───────────────────────────────────────────────────────────────

type TCPReader struct {
	Conn net.Conn
}

func (r *TCPReader) Read(n int) ([]byte, map[string]bool, error) {
	buf := make([]byte, n)
	got, err := r.Conn.Read(buf)
	if err != nil {
		return nil, nil, err
	}
	return buf[:got], nil, nil
}

func (r *TCPReader) ReadExactly(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(r.Conn, buf)
	return buf, err
}

type TCPWriter struct {
	Conn net.Conn
}

func (w *TCPWriter) Write(data []byte, extra map[string]bool) error {
	_, err := w.Conn.Write(data)
	return err
}

func (w *TCPWriter) WriteEOF() error {
	if tc, ok := w.Conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return nil
}

func (w *TCPWriter) Drain() error      { return nil }
func (w *TCPWriter) Close()            { w.Conn.Close() }
func (w *TCPWriter) Abort()            { w.Conn.Close() }
func (w *TCPWriter) GetConn() net.Conn { return w.Conn }

// ── FakeTLS 流 ────────────────────────────────────────────────────────────────

type FakeTLSReader struct {
	Upstream StreamReader
	Buf      []byte
}

func (r *FakeTLSReader) ReadExactly(n int) ([]byte, error) {
	for len(r.Buf) < n {
		data, _, err := r.readRecord()
		if err != nil {
			return nil, err
		}
		r.Buf = append(r.Buf, data...)
	}
	out := make([]byte, n)
	copy(out, r.Buf[:n])
	r.Buf = r.Buf[n:]
	return out, nil
}

func (r *FakeTLSReader) Read(n int) ([]byte, map[string]bool, error) {
	if len(r.Buf) > 0 {
		out := r.Buf
		r.Buf = nil
		return out, nil, nil
	}
	data, _, err := r.readRecord()
	return data, nil, err
}

func (r *FakeTLSReader) readRecord() ([]byte, byte, error) {
	for {
		recType, err := r.Upstream.ReadExactly(1)
		if err != nil {
			return nil, 0, err
		}
		version, err := r.Upstream.ReadExactly(2)
		if err != nil {
			return nil, 0, err
		}
		if version[0] != 0x03 {
			return nil, 0, fmt.Errorf("unknown TLS version: %x", version)
		}
		lenBytes, err := r.Upstream.ReadExactly(2)
		if err != nil {
			return nil, 0, err
		}
		dataLen := int(binary.BigEndian.Uint16(lenBytes))
		data, err := r.Upstream.ReadExactly(dataLen)
		if err != nil {
			return nil, 0, err
		}
		if recType[0] == 0x14 { // change cipher spec, skip
			continue
		}
		return data, recType[0], nil
	}
}

type FakeTLSWriter struct {
	Upstream StreamWriter
}

// drsChunkSize 根据动态记录大小（DRS）策略返回下一个分片大小，
// 模仿真实 TLS 1.3（Chrome / BoringSSL）的三阶段行为：
//
//	阶段 1（written == 0）：
//	  首包约 1 MTU（1400 B），让 TCP 慢启动快速确认可达性。
//
//	阶段 2（written < initSize*4，即 < 5600 B）：
//	  下一块大小 = 上一块大小 × 2，实现指数增长。
//	  注意：此处 nextSize 基于"上一块实际大小"而非 written 总量，
//	  由调用方通过 lastChunk 参数传入。
//
//	阶段 3（written >= 5600 B）：
//	  稳定在最大记录 16384 B 附近，加 ±512 B 随机抖动，
//	  避免固定包长被 DPI 识别。
//
// 参数：
//
//	remaining  — 本次 Write 中尚未写出的字节数
//	lastChunk  — 上一块实际写出的字节数（首块传 0）
func drsChunkSize(remaining, lastChunk int) int {
	const (
		initSize = 1400  // 阶段1：约 1 个 MTU
		maxSize  = 16384 // TLS 记录净荷上限（RFC 8446）
		jitter   = 512   // 阶段3 随机抖动范围
	)

	var target int
	switch {
	case lastChunk == 0:
		// 阶段 1：首包小包
		target = initSize
	case lastChunk < initSize*4:
		// 阶段 2：上一块翻倍（指数增长）
		target = lastChunk * 2
	default:
		// 阶段 3：稳定阶段，加随机抖动
		j := crypto.GlobalRand.Intn(jitter*2+1) - jitter // [-512, +512]
		target = maxSize + j
	}

	if target > maxSize {
		target = maxSize
	}
	if target > remaining {
		target = remaining
	}
	if target <= 0 {
		target = 1
	}
	return target
}

func (w *FakeTLSWriter) Write(data []byte, extra map[string]bool) error {
	written := 0
	lastChunk := 0
	for written < len(data) {
		chunkSize := drsChunkSize(len(data)-written, lastChunk)
		chunk := data[written : written+chunkSize]
		// 将 TLS 记录头（5 字节）和 payload 合并为单次写入，避免拆成两个 TCP 包
		record := make([]byte, 5+len(chunk))
		record[0] = 0x17
		record[1] = 0x03
		record[2] = 0x03
		record[3] = byte(len(chunk) >> 8)
		record[4] = byte(len(chunk))
		copy(record[5:], chunk)
		if err := w.Upstream.Write(record, nil); err != nil {
			return err
		}
		written += chunkSize
		lastChunk = chunkSize
	}
	return nil
}

func (w *FakeTLSWriter) WriteEOF() error   { return w.Upstream.WriteEOF() }
func (w *FakeTLSWriter) Drain() error      { return w.Upstream.Drain() }
func (w *FakeTLSWriter) Close()            { w.Upstream.Close() }
func (w *FakeTLSWriter) Abort()            { w.Upstream.Abort() }
func (w *FakeTLSWriter) GetConn() net.Conn { return w.Upstream.GetConn() }

// ── Crypto 流 ─────────────────────────────────────────────────────────────────

type CryptoReader struct {
	Upstream  StreamReader
	Decryptor crypto.Cipher
	BlockSize int
	Buf       []byte
}

func (r *CryptoReader) ReadExactly(n int) ([]byte, error) {
	for len(r.Buf) < n {
		toRead := n - len(r.Buf)
		aligned := toRead
		if r.BlockSize > 1 {
			rem := toRead % r.BlockSize
			if rem != 0 {
				aligned += r.BlockSize - rem
			}
		}
		raw, err := r.Upstream.ReadExactly(aligned)
		if err != nil {
			return nil, err
		}
		r.Buf = append(r.Buf, r.Decryptor.Decrypt(raw)...)
	}
	out := make([]byte, n)
	copy(out, r.Buf[:n])
	r.Buf = r.Buf[n:]
	return out, nil
}

func (r *CryptoReader) Read(n int) ([]byte, map[string]bool, error) {
	if len(r.Buf) > 0 {
		out := r.Buf
		r.Buf = nil
		return out, nil, nil
	}
	raw, extra, err := r.Upstream.Read(n)
	if err != nil || len(raw) == 0 {
		return raw, extra, err
	}
	return r.Decryptor.Decrypt(raw), extra, nil
}

type CryptoWriter struct {
	Upstream  StreamWriter
	Encryptor crypto.Cipher
	BlockSize int
}

func (w *CryptoWriter) Write(data []byte, extra map[string]bool) error {
	if w.BlockSize > 1 && len(data)%w.BlockSize != 0 {
		return fmt.Errorf("data len %d not aligned to block size %d", len(data), w.BlockSize)
	}
	return w.Upstream.Write(w.Encryptor.Encrypt(data), extra)
}

func (w *CryptoWriter) WriteEOF() error   { return w.Upstream.WriteEOF() }
func (w *CryptoWriter) Drain() error      { return w.Upstream.Drain() }
func (w *CryptoWriter) Close()            { w.Upstream.Close() }
func (w *CryptoWriter) Abort()            { w.Upstream.Abort() }
func (w *CryptoWriter) GetConn() net.Conn { return w.Upstream.GetConn() }
