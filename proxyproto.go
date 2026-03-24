package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// handleProxyProtocol 解析 HAProxy PROXY protocol v1/v2
// 返回真实的客户端地址，出错返回 nil
func handleProxyProtocol(reader streamReader, peer net.Addr) (net.Addr, error) {
	const (
		proxyMinLen  = 6
		proxy2MinLen = 16
	)

	proxySig := []byte("PROXY ")
	proxy2Sig := []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}

	header, err := reader.ReadExactly(proxyMinLen)
	if err != nil {
		return nil, err
	}

	// proxy protocol v1
	if string(header) == string(proxySig) {
		// 读到 \r\n
		var line []byte
		line = append(line, header...)
		for {
			b, err := reader.ReadExactly(1)
			if err != nil {
				return nil, err
			}
			line = append(line, b...)
			if len(line) >= 2 && line[len(line)-2] == '\r' && line[len(line)-1] == '\n' {
				break
			}
			if len(line) > 108 {
				return nil, fmt.Errorf("proxy v1 header too long")
			}
		}

		// "PROXY TCP4 1.2.3.4 5.6.7.8 1234 5678\r\n"
		parts := strings.Fields(strings.TrimRight(string(line), "\r\n"))
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

	// proxy protocol v2 — 先读完 16 字节头
	rest, err := reader.ReadExactly(proxy2MinLen - proxyMinLen)
	if err != nil {
		return nil, err
	}
	header = append(header, rest...)

	if !startsWith(header, proxy2Sig) {
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

	// 0x20 = LOCAL, 0x21 = PROXY
	if proxyVer == 0x20 {
		return peer, nil
	}
	if proxyVer != 0x21 {
		return nil, fmt.Errorf("unsupported proxy v2 command")
	}

	proxyFam := header[13] >> 4
	const (
		af_unspec = 0x0
		af_inet   = 0x1
		af_inet6  = 0x2
	)

	switch proxyFam {
	case af_unspec:
		return peer, nil
	case af_inet:
		if proxyLen >= (4+2)*2 {
			srcIP := net.IP(addrData[:4])
			srcPort := int(binary.BigEndian.Uint16(addrData[8:10]))
			return &net.TCPAddr{IP: srcIP, Port: srcPort}, nil
		}
	case af_inet6:
		if proxyLen >= (16+2)*2 {
			srcIP := net.IP(addrData[:16])
			srcPort := int(binary.BigEndian.Uint16(addrData[32:34]))
			return &net.TCPAddr{IP: srcIP, Port: srcPort}, nil
		}
	}

	return nil, fmt.Errorf("bad proxy v2 address data")
}

func startsWith(data, prefix []byte) bool {
	if len(data) < len(prefix) {
		return false
	}
	for i, b := range prefix {
		if data[i] != b {
			return false
		}
	}
	return true
}
