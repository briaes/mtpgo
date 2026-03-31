package main

import "encoding/hex"

const (
	SkipLen      = 8
	PrekeyLen    = 32
	KeyLen       = 32
	IVLen        = 16
	HandshakeLen = 64
	ProtoTagPos  = 56
	DCIdxPos     = 60

	MinCertLen = 1024

	CBCPadding = 16
	MinMsgLen  = 12
	MaxMsgLen  = 1 << 24
)

var (
	ProtoTagAbridged     = []byte{0xef, 0xef, 0xef, 0xef}
	ProtoTagIntermediate = []byte{0xee, 0xee, 0xee, 0xee}
	ProtoTagSecure       = []byte{0xdd, 0xdd, 0xdd, 0xdd}
	PaddingFiller        = []byte{0x04, 0x00, 0x00, 0x00}
)

// 运行时会更新
var TGMiddleProxiesV4 = map[int][][2]interface{}{
	1: {{"149.154.175.50", 8888}}, -1: {{"149.154.175.50", 8888}},
	2: {{"149.154.161.144", 8888}}, -2: {{"149.154.161.144", 8888}},
	3: {{"149.154.175.100", 8888}}, -3: {{"149.154.175.100", 8888}},
	4: {{"91.108.4.136", 8888}}, -4: {{"149.154.165.109", 8888}},
	5: {{"91.108.56.183", 8888}}, -5: {{"91.108.56.183", 8888}},
}

var TGMiddleProxiesV6 = map[int][][2]interface{}{
	1: {{"2001:b28:f23d:f001::d", 8888}}, -1: {{"2001:b28:f23d:f001::d", 8888}},
	2: {{"2001:67c:04e8:f002::d", 80}}, -2: {{"2001:67c:04e8:f002::d", 80}},
	3: {{"2001:b28:f23d:f003::d", 8888}}, -3: {{"2001:b28:f23d:f003::d", 8888}},
	4: {{"2001:67c:04e8:f004::d", 8888}}, -4: {{"2001:67c:04e8:f004::d", 8888}},
	5: {{"2001:b28:f23f:f005::d", 8888}}, -5: {{"2001:b28:f23f:f005::d", 8888}},
}

var proxySecretHex = "c4f9faca9678e6bb48ad6c7e2ce5c0d24430645d554addeb55419e034da62721" +
	"d046eaab6e52ab14a95a443ecfb3463e79a05a66612adf9caeda8be9a80da698" +
	"6fb0a6ff387af84d88ef3a6413713e5c3377f6e1a3d47d99f5e0c56eece8f05c" +
	"54c490b079e31bef82ff0ee8f2b0a32756d249c5f21269816cb7061b265db212"

var ProxySecret, _ = hex.DecodeString(proxySecretHex)

var StatDurationBuckets = []float64{0.1, 0.5, 1, 2, 5, 15, 60, 300, 600, 1800, 1e9}
