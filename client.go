package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

func pipeReaderToWriter(ctx context.Context, rd streamReader, wr streamWriter,
	secretHex string, bufSize int, isUpstream bool) {

	defer func() { recover() }()
	stat := globalStats.GetOrCreateSecretStat(secretHex)

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
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func handleBadClient(conn net.Conn, handshake []byte, cfg *Config) {
	globalStats.IncConnectsBad()
	if !cfg.Mask || handshake == nil {
		io.Copy(io.Discard, conn)
		return
	}
	maskConn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", cfg.MaskHost, cfg.MaskPort), 5*time.Second)
	if err != nil {
		return
	}
	defer maskConn.Close()
	if len(handshake) > 0 {
		maskConn.Write(handshake)
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(maskConn, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, maskConn); done <- struct{}{} }()
	<-done
}

func handleClient(conn net.Conn, cfg *Config) {
	defer conn.Close()

	setKeepalive(conn, cfg.ClientKeepalive)
	globalStats.IncConnectsAll()

	hsResult, handshake, err := func() (*handshakeResult, []byte, error) {
		done := make(chan struct{})
		var res *handshakeResult
		var hs []byte
		var hsErr error
		go func() {
			res, hs, hsErr = handleHandshake(conn, cfg)
			close(done)
		}()
		select {
		case <-time.After(time.Duration(cfg.ClientHandshakeTimeout) * time.Second):
			globalStats.IncHandshakeTimeouts()
			return nil, nil, fmt.Errorf("handshake timeout")
		case <-done:
			return res, hs, hsErr
		}
	}()

	if err != nil {
		dbgf(cfg, "[DEBUG] handshake failed from %s: %v\n", conn.RemoteAddr(), err)
		if handshake != nil {
			handleBadClient(conn, handshake, cfg)
		}
		return
	}

	dbgf(cfg, "[DEBUG] handshake OK: proto=%x dc=%d secret=%s\n",
		hsResult.protoTag, hsResult.dcIdx, hsResult.secretHex[:8])

	stat := globalStats.GetOrCreateSecretStat(hsResult.secretHex)
	stat.IncConnects()
	stat.AddCurrConnects(1)
	defer stat.AddCurrConnects(-1)

	var tgReader streamReader
	var tgWriter streamWriter

	clAddr := conn.RemoteAddr().(*net.TCPAddr)
	dbgf(cfg, "[DEBUG] connecting via middleproxy dc=%d\n", hsResult.dcIdx)
	tgReader, tgWriter, err = doMiddleproxyHandshake(hsResult.protoTag, hsResult.dcIdx,
		clAddr.IP.String(), clAddr.Port, cfg)

	if err != nil {
		dbgf(cfg, "[DEBUG] TG connect failed: %v\n", err)
		return
	}
	dbgf(cfg, "[DEBUG] TG connected OK\n")
	defer tgWriter.Abort()

	cltReader := hsResult.reader
	cltWriter := hsResult.writer

	if bytes.Equal(hsResult.protoTag, ProtoTagAbridged) {
		cltReader = &mtprotoCompactReader{upstream: cltReader}
		cltWriter = &mtprotoCompactWriter{upstream: cltWriter}
	} else if bytes.Equal(hsResult.protoTag, ProtoTagIntermediate) {
		cltReader = &mtprotoIntermediateReader{upstream: cltReader}
		cltWriter = &mtprotoIntermediateWriter{upstream: cltWriter}
	} else if bytes.Equal(hsResult.protoTag, ProtoTagSecure) {
		cltReader = &mtprotoSecureReader{upstream: cltReader}
		cltWriter = &mtprotoSecureWriter{upstream: cltWriter}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	done := make(chan struct{}, 2)
	go func() {
		pipeReaderToWriter(ctx, tgReader, cltWriter, hsResult.secretHex, 1<<17, false)
		done <- struct{}{}
	}()
	go func() {
		pipeReaderToWriter(ctx, cltReader, tgWriter, hsResult.secretHex, 1<<17, true)
		done <- struct{}{}
	}()

	<-done
	cancel()
	globalStats.UpdateDuration(time.Since(start).Seconds())
}

func handleClientWrapper(conn net.Conn, cfg *Config) {
	defer func() {
		recover()
		conn.Close()
	}()
	handleClient(conn, cfg)
}

func setKeepalive(conn net.Conn, interval int) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(time.Duration(interval) * time.Second)
	}
}
