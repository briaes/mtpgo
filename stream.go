package main

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"net"
)

// ── 基础接口 ──────────────────────────────────────────────────────────────────

type streamReader interface {
	Read(n int) ([]byte, map[string]bool, error)
	ReadExactly(n int) ([]byte, error)
}

type streamWriter interface {
	Write(data []byte, extra map[string]bool) error
	WriteEOF() error
	Drain() error
	Close()
	Abort()
	GetConn() net.Conn
}

// ── 基础 TCP 流 ───────────────────────────────────────────────────────────────

type tcpReader struct {
	conn net.Conn
}

func (r *tcpReader) Read(n int) ([]byte, map[string]bool, error) {
	buf := make([]byte, n)
	got, err := r.conn.Read(buf)
	if err != nil {
		return nil, nil, err
	}
	return buf[:got], nil, nil
}

func (r *tcpReader) ReadExactly(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(r.conn, buf)
	return buf, err
}

type tcpWriter struct {
	conn net.Conn
}

func (w *tcpWriter) Write(data []byte, extra map[string]bool) error {
	_, err := w.conn.Write(data)
	return err
}

func (w *tcpWriter) WriteEOF() error {
	if tc, ok := w.conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return nil
}

func (w *tcpWriter) Drain() error  { return nil }
func (w *tcpWriter) Close()        { w.conn.Close() }
func (w *tcpWriter) Abort()        { w.conn.Close() }
func (w *tcpWriter) GetConn() net.Conn { return w.conn }

// ── FakeTLS 流 ────────────────────────────────────────────────────────────────

type fakeTLSReader struct {
	upstream streamReader
	buf      []byte
}

func (r *fakeTLSReader) ReadExactly(n int) ([]byte, error) {
	for len(r.buf) < n {
		data, _, err := r.readRecord()
		if err != nil {
			return nil, err
		}
		r.buf = append(r.buf, data...)
	}
	out := make([]byte, n)
	copy(out, r.buf[:n])
	r.buf = r.buf[n:]
	return out, nil
}

func (r *fakeTLSReader) Read(n int) ([]byte, map[string]bool, error) {
	if len(r.buf) > 0 {
		out := r.buf
		r.buf = nil
		return out, nil, nil
	}
	data, _, err := r.readRecord()
	return data, nil, err
}

func (r *fakeTLSReader) readRecord() ([]byte, byte, error) {
	for {
		recType, err := r.upstream.ReadExactly(1)
		if err != nil {
			return nil, 0, err
		}
		version, err := r.upstream.ReadExactly(2)
		if err != nil {
			return nil, 0, err
		}
		if version[0] != 0x03 {
			return nil, 0, fmt.Errorf("unknown TLS version: %x", version)
		}
		lenBytes, err := r.upstream.ReadExactly(2)
		if err != nil {
			return nil, 0, err
		}
		dataLen := int(binary.BigEndian.Uint16(lenBytes))
		data, err := r.upstream.ReadExactly(dataLen)
		if err != nil {
			return nil, 0, err
		}
		if recType[0] == 0x14 { // change cipher spec, skip
			continue
		}
		return data, recType[0], nil
	}
}

type fakeTLSWriter struct {
	upstream streamWriter
}

func (w *fakeTLSWriter) Write(data []byte, extra map[string]bool) error {
	const maxChunk = 16384 + 24
	for start := 0; start < len(data); start += maxChunk {
		end := start + maxChunk
		if end > len(data) {
			end = len(data)
		}
		chunk := data[start:end]
		hdr := []byte{0x17, 0x03, 0x03, byte(len(chunk) >> 8), byte(len(chunk))}
		if err := w.upstream.Write(hdr, nil); err != nil {
			return err
		}
		if err := w.upstream.Write(chunk, nil); err != nil {
			return err
		}
	}
	return nil
}

func (w *fakeTLSWriter) WriteEOF() error       { return w.upstream.WriteEOF() }
func (w *fakeTLSWriter) Drain() error          { return w.upstream.Drain() }
func (w *fakeTLSWriter) Close()                { w.upstream.Close() }
func (w *fakeTLSWriter) Abort()                { w.upstream.Abort() }
func (w *fakeTLSWriter) GetConn() net.Conn     { return w.upstream.GetConn() }

// ── Crypto 流 ─────────────────────────────────────────────────────────────────

type cryptoReader struct {
	upstream  streamReader
	decryptor interface{ decrypt([]byte) []byte }
	blockSize int
	buf       []byte
}

func (r *cryptoReader) ReadExactly(n int) ([]byte, error) {
	for len(r.buf) < n {
		toRead := n - len(r.buf)
		aligned := toRead
		if r.blockSize > 1 {
			rem := toRead % r.blockSize
			if rem != 0 {
				aligned += r.blockSize - rem
			}
		}
		raw, err := r.upstream.ReadExactly(aligned)
		if err != nil {
			return nil, err
		}
		r.buf = append(r.buf, r.decryptor.decrypt(raw)...)
	}
	out := make([]byte, n)
	copy(out, r.buf[:n])
	r.buf = r.buf[n:]
	return out, nil
}

func (r *cryptoReader) Read(n int) ([]byte, map[string]bool, error) {
	if len(r.buf) > 0 {
		out := r.buf
		r.buf = nil
		return out, nil, nil
	}
	raw, extra, err := r.upstream.Read(n)
	if err != nil || len(raw) == 0 {
		return raw, extra, err
	}
	return r.decryptor.decrypt(raw), extra, nil
}

type cryptoWriter struct {
	upstream  streamWriter
	encryptor interface{ encrypt([]byte) []byte }
	blockSize int
}

func (w *cryptoWriter) Write(data []byte, extra map[string]bool) error {
	if w.blockSize > 1 && len(data)%w.blockSize != 0 {
		return fmt.Errorf("data len %d not aligned to block size %d", len(data), w.blockSize)
	}
	return w.upstream.Write(w.encryptor.encrypt(data), extra)
}

func (w *cryptoWriter) WriteEOF() error   { return w.upstream.WriteEOF() }
func (w *cryptoWriter) Drain() error      { return w.upstream.Drain() }
func (w *cryptoWriter) Close()            { w.upstream.Close() }
func (w *cryptoWriter) Abort()            { w.upstream.Abort() }
func (w *cryptoWriter) GetConn() net.Conn { return w.upstream.GetConn() }

// ── MTProto Frame 流（用于中间代理） ──────────────────────────────────────────

type mtprotoFrameReader struct {
	upstream streamReader
	seqNo    int32
}

func (r *mtprotoFrameReader) ReadExactly(n int) ([]byte, error) {
	data, _, err := r.Read(n)
	return data, err
}

func (r *mtprotoFrameReader) Read(bufSize int) ([]byte, map[string]bool, error) {
	for {
		lenBytes, err := r.upstream.ReadExactly(4)
		if err != nil {
			return nil, nil, err
		}
		msgLen := int(binary.LittleEndian.Uint32(lenBytes))
		if msgLen == 4 {
			continue // padding
		}
		if msgLen < MinMsgLen || msgLen > MaxMsgLen || msgLen%len(PaddingFiller) != 0 {
			return nil, nil, fmt.Errorf("bad msg_len: %d", msgLen)
		}
		seqBytes, err := r.upstream.ReadExactly(4)
		if err != nil {
			return nil, nil, err
		}
		seq := int32(binary.LittleEndian.Uint32(seqBytes))
		if seq != r.seqNo {
			return nil, nil, fmt.Errorf("unexpected seq_no: got %d want %d", seq, r.seqNo)
		}
		r.seqNo++
		data, err := r.upstream.ReadExactly(msgLen - 4 - 4 - 4)
		if err != nil {
			return nil, nil, err
		}
		checksumBytes, err := r.upstream.ReadExactly(4)
		if err != nil {
			return nil, nil, err
		}
		checksum := binary.LittleEndian.Uint32(checksumBytes)
		computed := crc32.ChecksumIEEE(append(append(lenBytes, seqBytes...), data...))
		if computed != checksum {
			return nil, nil, fmt.Errorf("crc32 mismatch")
		}
		return data, nil, nil
	}
}

type mtprotoFrameWriter struct {
	upstream streamWriter
	seqNo    int32
}

func (w *mtprotoFrameWriter) Write(msg []byte, extra map[string]bool) error {
	totalLen := len(msg) + 4 + 4 + 4
	lenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBytes, uint32(totalLen))
	seqBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(seqBytes, uint32(w.seqNo))
	w.seqNo++

	withoutChecksum := append(append(lenBytes, seqBytes...), msg...)
	checksum := crc32.ChecksumIEEE(withoutChecksum)
	csBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(csBytes, checksum)

	full := append(withoutChecksum, csBytes...)
	// padding
	rem := len(full) % CBCPadding
	if rem != 0 {
		for i := 0; i < CBCPadding-rem; i += len(PaddingFiller) {
			full = append(full, PaddingFiller...)
		}
	}
	return w.upstream.Write(full, extra)
}

func (w *mtprotoFrameWriter) WriteEOF() error   { return w.upstream.WriteEOF() }
func (w *mtprotoFrameWriter) Drain() error      { return w.upstream.Drain() }
func (w *mtprotoFrameWriter) Close()            { w.upstream.Close() }
func (w *mtprotoFrameWriter) Abort()            { w.upstream.Abort() }
func (w *mtprotoFrameWriter) GetConn() net.Conn { return w.upstream.GetConn() }

// ── MTProto Compact (Abridged) 帧流 ──────────────────────────────────────────

type mtprotoCompactReader struct{ upstream streamReader }

func (r *mtprotoCompactReader) ReadExactly(n int) ([]byte, error) {
	data, _, err := r.Read(n)
	return data, err
}

func (r *mtprotoCompactReader) Read(bufSize int) ([]byte, map[string]bool, error) {
	hdr, err := r.upstream.ReadExactly(1)
	if err != nil {
		return nil, nil, err
	}
	msgLen := int(hdr[0])
	extra := map[string]bool{}
	if msgLen >= 0x80 {
		extra["QUICKACK_FLAG"] = true
		msgLen -= 0x80
	}
	if msgLen == 0x7f {
		ext, err := r.upstream.ReadExactly(3)
		if err != nil {
			return nil, nil, err
		}
		msgLen = int(ext[0]) | int(ext[1])<<8 | int(ext[2])<<16
	}
	msgLen *= 4
	data, err := r.upstream.ReadExactly(msgLen)
	return data, extra, err
}

type mtprotoCompactWriter struct{ upstream streamWriter }

func (w *mtprotoCompactWriter) Write(data []byte, extra map[string]bool) error {
	if extra != nil && extra["SIMPLE_ACK"] {
		rev := make([]byte, len(data))
		for i, b := range data {
			rev[len(data)-1-i] = b
		}
		return w.upstream.Write(rev, nil)
	}
	lenDiv4 := len(data) / 4
	var hdr []byte
	if lenDiv4 < 0x7f {
		hdr = []byte{byte(lenDiv4)}
	} else {
		hdr = []byte{0x7f, byte(lenDiv4), byte(lenDiv4 >> 8), byte(lenDiv4 >> 16)}
	}
	return w.upstream.Write(append(hdr, data...), nil)
}

func (w *mtprotoCompactWriter) WriteEOF() error   { return w.upstream.WriteEOF() }
func (w *mtprotoCompactWriter) Drain() error      { return w.upstream.Drain() }
func (w *mtprotoCompactWriter) Close()            { w.upstream.Close() }
func (w *mtprotoCompactWriter) Abort()            { w.upstream.Abort() }
func (w *mtprotoCompactWriter) GetConn() net.Conn { return w.upstream.GetConn() }

// ── MTProto Intermediate 帧流 ─────────────────────────────────────────────────

type mtprotoIntermediateReader struct{ upstream streamReader }

func (r *mtprotoIntermediateReader) ReadExactly(n int) ([]byte, error) {
	data, _, err := r.Read(n)
	return data, err
}

func (r *mtprotoIntermediateReader) Read(bufSize int) ([]byte, map[string]bool, error) {
	hdr, err := r.upstream.ReadExactly(4)
	if err != nil {
		return nil, nil, err
	}
	msgLen := binary.LittleEndian.Uint32(hdr)
	extra := map[string]bool{}
	if msgLen > 0x80000000 {
		extra["QUICKACK_FLAG"] = true
		msgLen -= 0x80000000
	}
	data, err := r.upstream.ReadExactly(int(msgLen))
	return data, extra, err
}

type mtprotoIntermediateWriter struct{ upstream streamWriter }

func (w *mtprotoIntermediateWriter) Write(data []byte, extra map[string]bool) error {
	if extra != nil && extra["SIMPLE_ACK"] {
		return w.upstream.Write(data, nil)
	}
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint32(hdr, uint32(len(data)))
	return w.upstream.Write(append(hdr, data...), nil)
}

func (w *mtprotoIntermediateWriter) WriteEOF() error   { return w.upstream.WriteEOF() }
func (w *mtprotoIntermediateWriter) Drain() error      { return w.upstream.Drain() }
func (w *mtprotoIntermediateWriter) Close()            { w.upstream.Close() }
func (w *mtprotoIntermediateWriter) Abort()            { w.upstream.Abort() }
func (w *mtprotoIntermediateWriter) GetConn() net.Conn { return w.upstream.GetConn() }

// ── MTProto Secure Intermediate 帧流 ─────────────────────────────────────────

type mtprotoSecureReader struct{ upstream streamReader }

func (r *mtprotoSecureReader) ReadExactly(n int) ([]byte, error) {
	data, _, err := r.Read(n)
	return data, err
}

func (r *mtprotoSecureReader) Read(bufSize int) ([]byte, map[string]bool, error) {
	hdr, err := r.upstream.ReadExactly(4)
	if err != nil {
		return nil, nil, err
	}
	raw := binary.LittleEndian.Uint32(hdr)
	extra := map[string]bool{}
	if raw > 0x80000000 {
		extra["QUICKACK_FLAG"] = true
		raw -= 0x80000000
	}
	msgLen := int(raw)
	data, err := r.upstream.ReadExactly(msgLen)
	if err != nil {
		return nil, nil, err
	}
	if msgLen%4 != 0 {
		data = data[:msgLen-(msgLen%4)]
	}
	return data, extra, nil
}

type mtprotoSecureWriter struct{ upstream streamWriter }

func (w *mtprotoSecureWriter) Write(data []byte, extra map[string]bool) error {
	if extra != nil && extra["SIMPLE_ACK"] {
		return w.upstream.Write(data, nil)
	}
	paddingLen := globalRand.Intn(4)
	padding := globalRand.Bytes(paddingLen)
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint32(hdr, uint32(len(data)+paddingLen))
	return w.upstream.Write(append(append(hdr, data...), padding...), nil)
}

func (w *mtprotoSecureWriter) WriteEOF() error   { return w.upstream.WriteEOF() }
func (w *mtprotoSecureWriter) Drain() error      { return w.upstream.Drain() }
func (w *mtprotoSecureWriter) Close()            { w.upstream.Close() }
func (w *mtprotoSecureWriter) Abort()            { w.upstream.Abort() }
func (w *mtprotoSecureWriter) GetConn() net.Conn { return w.upstream.GetConn() }
