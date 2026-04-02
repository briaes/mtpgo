package proto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// HandleProxyProtocol 解析 HAProxy PROXY protocol v1/v2，返回真实的客户端地址。
func HandleProxyProtocol(reader StreamReader, peer net.Addr) (net.Addr, error) {
	const (
		proxyMinLen  = 6
		proxy2MinLen = 16
		// v1 最大行长：108 字节（规范上限）
		proxy1MaxLine = 108
	)

	proxySig := []byte("PROXY ")
	proxy2Sig := []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}

	header, err := reader.ReadExactly(proxyMinLen)
	if err != nil {
		return nil, err
	}

	// ── Proxy Protocol v1 ─────────────────────────────────────────────────────
	if bytes.Equal(header, proxySig) {
		// 修复：一次读取最大可能的 v1 行（108 字节），再找 \r\n，
		// 替代原来逐字节读取的低效方式。
		rest, err := reader.ReadExactly(proxy1MaxLine - proxyMinLen)
		if err != nil {
			return nil, err
		}
		line := append(header, rest...)
		idx := bytes.Index(line, []byte("\r\n"))
		if idx < 0 {
			return nil, fmt.Errorf("proxy v1 header: no CRLF found")
		}
		line = line[:idx]

		// "PROXY TCP4 1.2.3.4 5.6.7.8 1234 5678"
		parts := strings.Fields(string(line))
		if len(parts) < 2 {
			return nil, fmt.Errorf("bad proxy v1 header")
		}
		family := parts[1]
		if family == "UNKNOWN" {
			return peer, nil
		}
		if (family == "TCP4" || family == "TCP6") && len(parts) == 6 {
			srcAddr := parts[2]
			srcPort, err := strconv.Atoi(parts[4])
			if err != nil {
				return nil, fmt.Errorf("bad proxy v1 src port")
			}
			return &net.TCPAddr{IP: net.ParseIP(srcAddr), Port: srcPort}, nil
		}
		return nil, fmt.Errorf("unsupported proxy v1 family: %s", family)
	}

	// ── Proxy Protocol v2 ─────────────────────────────────────────────────────
	// 修复：用 bytes.HasPrefix 替代手写的 startsWith 循环
	rest, err := reader.ReadExactly(proxy2MinLen - proxyMinLen)
	if err != nil {
		return nil, err
	}
	header = append(header, rest...)

	if !bytes.HasPrefix(header, proxy2Sig) {
		return nil, fmt.Errorf("unknown proxy protocol")
	}

	proxyVer := header[12]
	if proxyVer&0xf0 != 0x20 {
		return nil, fmt.Errorf("bad proxy v2 version")
	}

	proxyLen := int(binary.BigEndian.Uint16(header[14:16]))
	addrData, err := reader.ReadExactly(proxyLen)
	if err != nil {
		return nil, err
	}

	// 0x20 = LOCAL（保留原始对端地址），0x21 = PROXY（使用头中地址）
	if proxyVer == 0x20 {
		return peer, nil
	}
	if proxyVer != 0x21 {
		return nil, fmt.Errorf("unsupported proxy v2 command")
	}

	proxyFam := header[13] >> 4
	const (
		afUnspec = 0x0
		afInet   = 0x1
		afInet6  = 0x2
	)

	switch proxyFam {
	case afUnspec:
		return peer, nil
	case afInet:
		if proxyLen >= (4+2)*2 {
			srcIP := net.IP(addrData[:4])
			srcPort := int(binary.BigEndian.Uint16(addrData[8:10]))
			return &net.TCPAddr{IP: srcIP, Port: srcPort}, nil
		}
	case afInet6:
		if proxyLen >= (16+2)*2 {
			srcIP := net.IP(addrData[:16])
			srcPort := int(binary.BigEndian.Uint16(addrData[32:34]))
			return &net.TCPAddr{IP: srcIP, Port: srcPort}, nil
		}
	}

	return nil, fmt.Errorf("bad proxy v2 address data")
}
