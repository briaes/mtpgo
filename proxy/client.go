package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"mtproxy/config"
	"mtproxy/proto"
	"mtproxy/stats"
)

// pipeReaderToWriter 将 rd 的数据转发到 wr，直到 ctx 取消或读写出错。
// conn 是底层 TCP 连接，ctx 取消时通过 conn.SetDeadline 使阻塞中的 Read
// 立即返回错误，避免 goroutine 一直挂起。
func pipeReaderToWriter(ctx context.Context, rd proto.StreamReader, wr proto.StreamWriter,
	conn net.Conn, secretHex string, bufSize int, isUpstream bool) {

	defer func() { recover() }()
	stat := stats.GlobalStats.GetOrCreateSecretStat(secretHex)

	// ctx 取消时设置过期 deadline，解除 conn 上阻塞的 Read
	go func() {
		<-ctx.Done()
		conn.SetDeadline(time.Now())
	}()

	for {
		data, extra, err := rd.Read(bufSize)
		if err != nil {
			return
		}
		if extra != nil && extra["SKIP_SEND"] {
			continue
		}
		if len(data) == 0 {
			wr.WriteEOF()
			return
		}
		if isUpstream {
			stat.AddOctetsFromClt(int64(len(data)))
			stat.AddMsgsFromClt(1)
		} else {
			stat.AddOctetsToClt(int64(len(data)))
			stat.AddMsgsToClt(1)
		}
		if err := wr.Write(data, extra); err != nil {
			return
		}
	}
}

// HandleBadClient 将握手失败的连接转发到 MaskHost，模拟真实 TLS 服务器。
// 修复：等待两个方向的 goroutine 都完成后再关闭连接，消除 goroutine 泄漏。
func HandleBadClient(conn net.Conn, handshake []byte, cfg *config.Config) {
	stats.GlobalStats.IncConnectsBad()
	if !cfg.Mask || handshake == nil {
		io.Copy(io.Discard, conn)
		return
	}
	maskConn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", cfg.MaskHost, cfg.MaskPort), 5*time.Second)
	if err != nil {
		io.Copy(io.Discard, conn)
		return
	}

	if len(handshake) > 0 {
		maskConn.Write(handshake)
	}

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(maskConn, conn)
		if tc, ok := maskConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, maskConn)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()

	// 等待两个方向都结束，再统一关闭，避免单边关闭导致另一 goroutine 泄漏
	<-done
	<-done
	maskConn.Close()
}

// HandleClient 处理单个客户端连接。
// 修复：握手超时通过 conn.SetDeadline 实现，超时后握手中的阻塞 IO 立即报错退出，
// 不再使用独立 goroutine + channel，消除超时时的 goroutine 泄漏。
func HandleClient(conn net.Conn, cfg *config.Config) {
	defer conn.Close()

	SetKeepalive(conn, cfg.ClientKeepalive)
	stats.GlobalStats.IncConnectsAll()

	// 握手阶段整体 deadline；超时后 conn 上所有阻塞 IO 立即返回 error，
	// HandleHandshake 自然退出，不再需要额外的 goroutine 看门。
	conn.SetDeadline(time.Now().Add(time.Duration(cfg.ClientHandshakeTimeout) * time.Second))
	hsResult, handshake, err := HandleHandshake(conn, cfg)
	// 握手结束后立即清除 deadline，恢复正常长连接
	conn.SetDeadline(time.Time{})

	if err != nil {
		stats.GlobalStats.IncHandshakeTimeouts()
		Dbgf(cfg, "[DEBUG] handshake failed from %s: %v\n", conn.RemoteAddr(), err)
		if handshake != nil {
			HandleBadClient(conn, handshake, cfg)
		}
		return
	}

	Dbgf(cfg, "[DEBUG] handshake OK: proto=%x dc=%d secret=%s\n",
		hsResult.ProtoTag, hsResult.DcIdx, hsResult.SecretHex[:8])

	stat := stats.GlobalStats.GetOrCreateSecretStat(hsResult.SecretHex)
	stat.IncConnects()
	stat.AddCurrConnects(1)
	defer stat.AddCurrConnects(-1)

	connectDirect := !cfg.UseMiddleProxy

	var tgReader proto.StreamReader
	var tgWriter proto.StreamWriter

	if connectDirect {
		var decKeyIV []byte
		if cfg.FastMode {
			decKeyIV = hsResult.EncKeyIV
		}
		Dbgf(cfg, "[DEBUG] connecting to TG dc=%d fastMode=%v\n", hsResult.DcIdx, cfg.FastMode)
		tgReader, tgWriter, err = DoDirectHandshake(hsResult.ProtoTag, hsResult.DcIdx, decKeyIV, cfg)
	} else {
		clAddr := conn.RemoteAddr().(*net.TCPAddr)
		Dbgf(cfg, "[DEBUG] connecting via middleproxy dc=%d\n", hsResult.DcIdx)
		tgReader, tgWriter, err = DoMiddleproxyHandshake(hsResult.ProtoTag, hsResult.DcIdx,
			clAddr.IP.String(), clAddr.Port, cfg)
	}

	if err != nil {
		Dbgf(cfg, "[DEBUG] TG connect failed: %v\n", err)
		return
	}
	Dbgf(cfg, "[DEBUG] TG connected OK\n")
	defer tgWriter.Abort()

	cltReader := hsResult.Reader
	cltWriter := hsResult.Writer

	if connectDirect && cfg.FastMode {
		if cr, ok := tgReader.(*proto.CryptoReader); ok {
			cr.Decryptor = &noopCipher{}
		}
		if cw, ok := cltWriter.(*proto.CryptoWriter); ok {
			cw.Encryptor = &noopCipher{}
		}
	}

	if !connectDirect {
		if bytes.Equal(hsResult.ProtoTag, proto.ProtoTagAbridged) {
			cltReader = &proto.MtprotoCompactReader{Upstream: cltReader}
			cltWriter = &proto.MtprotoCompactWriter{Upstream: cltWriter}
		} else if bytes.Equal(hsResult.ProtoTag, proto.ProtoTagIntermediate) {
			cltReader = &proto.MtprotoIntermediateReader{Upstream: cltReader}
			cltWriter = &proto.MtprotoIntermediateWriter{Upstream: cltWriter}
		} else if bytes.Equal(hsResult.ProtoTag, proto.ProtoTagSecure) {
			cltReader = &proto.MtprotoSecureReader{Upstream: cltReader}
			cltWriter = &proto.MtprotoSecureWriter{Upstream: cltWriter}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	done := make(chan struct{}, 2)
	go func() {
		pipeReaderToWriter(ctx, tgReader, cltWriter, tgWriter.GetConn(), hsResult.SecretHex, 1<<17, false)
		done <- struct{}{}
	}()
	go func() {
		pipeReaderToWriter(ctx, cltReader, tgWriter, conn, hsResult.SecretHex, 1<<17, true)
		done <- struct{}{}
	}()

	<-done
	cancel()
	stats.GlobalStats.UpdateDuration(time.Since(start).Seconds())
}

func HandleClientWrapper(conn net.Conn, cfg *config.Config) {
	defer func() {
		recover()
		conn.Close()
	}()
	HandleClient(conn, cfg)
}

func SetKeepalive(conn net.Conn, interval int) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(time.Duration(interval) * time.Second)
	}
}

type noopCipher struct{}

func (n *noopCipher) Encrypt(data []byte) []byte { return data }
func (n *noopCipher) Decrypt(data []byte) []byte { return data }
