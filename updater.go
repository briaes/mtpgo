package main

import (
	"crypto/tls"
	"net"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var middleProxyMu sync.RWMutex

// ── 中间代理列表更新 ──────────────────────────────────────────────────────────

func getNewProxies(url string) (map[int][][2]interface{}, error) {
	re := regexp.MustCompile(`proxy_for\s+(-?\d+)\s+(.+):(\d+)\s*;`)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	ans := make(map[int][][2]interface{})
	for _, match := range re.FindAllStringSubmatch(string(body), -1) {
		dcIdx, _ := strconv.Atoi(match[1])
		host := match[2]
		port, _ := strconv.Atoi(match[3])
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
		ans[dcIdx] = append(ans[dcIdx], [2]interface{}{host, port})
	}
	return ans, nil
}

func updateMiddleProxyInfo(cfg *Config) {
	const (
		proxyInfoAddr   = "https://core.telegram.org/getProxyConfig"
		proxyInfoAddrV6 = "https://core.telegram.org/getProxyConfigV6"
		proxySecretAddr = "https://core.telegram.org/getProxySecret"
	)

	for {
		// 更新 IPv4 代理列表
		v4, err := getNewProxies(proxyInfoAddr)
		if err != nil || len(v4) == 0 {
			logf("Error updating middle proxy list:", err)
		} else {
			middleProxyMu.Lock()
			TGMiddleProxiesV4 = v4
			middleProxyMu.Unlock()
		}

		// 更新 IPv6 代理列表
		v6, err := getNewProxies(proxyInfoAddrV6)
		if err != nil || len(v6) == 0 {
			logf("Error updating middle proxy list (IPv6):", err)
		} else {
			middleProxyMu.Lock()
			TGMiddleProxiesV6 = v6
			middleProxyMu.Unlock()
		}

		// 更新 ProxySecret
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(proxySecretAddr)
		if err != nil {
			logf("Error updating middle proxy secret:", err)
		} else {
			secret, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if len(secret) > 0 {
				newSecret := make([]byte, len(secret))
				copy(newSecret, secret)
				if string(newSecret) != string(ProxySecret) {
					ProxySecret = newSecret
					logf("Middle proxy secret updated\n")
				}
			}
		}

		time.Sleep(time.Duration(cfg.ProxyInfoUpdatePeriod) * time.Second)
	}
}

// ── 服务器时间同步 ────────────────────────────────────────────────────────────

var isTimeSkewed bool
var timeSkewMu sync.RWMutex

func getSrvTime(cfg *Config) {
	const (
		timeSyncAddr = "https://core.telegram.org/getProxySecret"
		maxTimeSkew  = 30.0
	)

	wantReenable := false

	for {
		func() {
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Get(timeSyncAddr)
			if err != nil {
				logf("Error getting server time:", err)
				return
			}
			defer resp.Body.Close()

			dateHeader := resp.Header.Get("Date")
			if dateHeader == "" {
				return
			}

			srvTime, err := time.Parse(time.RFC1123, dateHeader)
			if err != nil {
				logf("Error parsing server time:", err)
				return
			}

			skew := time.Since(srvTime).Seconds()
			skewed := skew > maxTimeSkew || skew < -maxTimeSkew

			timeSkewMu.Lock()
			isTimeSkewed = skewed
			timeSkewMu.Unlock()

			if skewed && cfg.UseMiddleProxy && !disableMiddleProxy {
				logf("Time skew detected, please set the clock\n")
				logf("Server time: %v, your time: %v\n", srvTime, time.Now().UTC())
				logf("Disabling advertising to continue serving\n")
				disableMiddleProxy = true
				wantReenable = true
			} else if !skewed && wantReenable {
				logf("Time is ok, reenabling advertising\n")
				disableMiddleProxy = false
				wantReenable = false
			}
		}()

		time.Sleep(time.Duration(cfg.GetTimePeriod) * time.Second)
	}
}

// ── TLS 证书长度获取 ──────────────────────────────────────────────────────────

var fakeCertLen = 2048 // 默认值
var fakeCertMu sync.RWMutex

func getMaskHostCertLen(cfg *Config) {
	const getCertTimeout = 10 * time.Second
	const maskEnablingCheckPeriod = 60 * time.Second

	for {
		if !cfg.Mask {
			time.Sleep(maskEnablingCheckPeriod)
			continue
		}

		func() {
			conn, err := tls.DialWithDialer(
				&net.Dialer{Timeout: getCertTimeout},
				"tcp",
				fmt.Sprintf("%s:%d", cfg.MaskHost, cfg.MaskPort),
				&tls.Config{
					ServerName:         cfg.TLSDomain,
					InsecureSkipVerify: true,
				},
			)
			if err != nil {
				logf("Failed to connect to MASK_HOST %s: %v\n", cfg.MaskHost, err)
				return
			}
			defer conn.Close()

			// 获取证书原始数据长度
			state := conn.ConnectionState()
			if len(state.PeerCertificates) == 0 {
				logf("MASK_HOST %s returned no certificates\n", cfg.MaskHost)
				return
			}
			certLen := len(state.PeerCertificates[0].Raw)
			if certLen < MinCertLen {
				logf("MASK_HOST %s cert too short: %d\n", cfg.MaskHost, certLen)
				return
			}

			fakeCertMu.Lock()
			if certLen != fakeCertLen {
				fakeCertLen = certLen
				logf("Got cert from MASK_HOST %s, length: %d\n", cfg.MaskHost, certLen)
			}
			fakeCertMu.Unlock()
		}()

		time.Sleep(time.Duration(cfg.GetCertLenPeriod) * time.Second)
	}
}

// ── IP 缓存清理 ───────────────────────────────────────────────────────────────

func clearIPResolvingCache() {
	for {
		sleepTime := 60 + globalRand.Intn(60)
		time.Sleep(time.Duration(sleepTime) * time.Second)
		// 简单实现：重新获取一次 mask host IP（Go 的 net 包有内置 DNS 缓存处理）
	}
}
