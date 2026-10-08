package session

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const defaultDevicePort = 8000

type Endpoint struct {
	URL    string
	Scheme string
	Host   string
	Port   int
}

func NormalizeDeviceAddress(raw string) (Endpoint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Endpoint{}, errors.New("device address is required")
	}
	if ip := net.ParseIP(raw); ip != nil {
		raw = (&url.URL{Scheme: "http", Host: net.JoinHostPort(ip.String(), strconv.Itoa(defaultDevicePort))}).String()
	} else if !strings.Contains(raw, "://") {
		host, port, err := net.SplitHostPort(raw)
		if err != nil || net.ParseIP(host) == nil {
			return Endpoint{}, errors.New("device address must be a literal IP")
		}
		raw = (&url.URL{Scheme: "http", Host: net.JoinHostPort(net.ParseIP(host).String(), port)}).String()
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return Endpoint{}, errors.New("device address scheme must be http or https")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.EscapedPath(), "/") != "" {
		return Endpoint{}, errors.New("device address must not contain credentials, path, query, or fragment")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil {
		return Endpoint{}, errors.New("device address must use a literal IP")
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || !privateSiteLocal(ip) {
		return Endpoint{}, errors.New("device address must be private or site-local")
	}
	port := defaultDevicePort
	if text := u.Port(); text != "" {
		port, err = strconv.Atoi(text)
		if err != nil || port <= 0 || port > 65535 {
			return Endpoint{}, errors.New("device port is invalid")
		}
	} else if u.Scheme == "https" {
		port = 443
	}
	host := ip.String()
	normalized := (&url.URL{Scheme: u.Scheme, Host: net.JoinHostPort(host, strconv.Itoa(port))}).String()
	return Endpoint{URL: normalized, Scheme: u.Scheme, Host: host, Port: port}, nil
}

func (e Endpoint) Masked() string {
	ip := net.ParseIP(e.Host)
	host := "private-address"
	if v4 := ip.To4(); v4 != nil {
		host = strconv.Itoa(int(v4[0])) + "." + strconv.Itoa(int(v4[1])) + ".*.*"
	} else if ip != nil {
		parts := strings.Split(ip.String(), ":")
		host = "[" + parts[0] + ":*]"
	}
	return strings.ToLower(e.Scheme) + "://" + host + ":" + strconv.Itoa(e.Port)
}

func endpointFingerprint(endpoint Endpoint, username string) string {
	canonical := endpoint.URL + "\x00" + strings.TrimSpace(username)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

func privateSiteLocal(ip net.IP) bool {
	if ip.IsPrivate() {
		return true
	}
	ip = ip.To16()
	return ip != nil && ip[0]&0xfe == 0xfc
}
