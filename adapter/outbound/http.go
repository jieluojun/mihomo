package outbound

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

type Http struct {
	*Base
	user      string
	pass      string
	tlsConfig *tls.Config
	option    *HttpOption
}

type HttpOption struct {
	BasicOption
	Name           string            `proxy:"name"`
	Server         string            `proxy:"server"`
	Port           int               `proxy:"port"`
	UserName       string            `proxy:"username,omitempty"`
	Password       string            `proxy:"password,omitempty"`
	TLS            bool              `proxy:"tls,omitempty"`
	SNI            string            `proxy:"sni,omitempty"`
	SkipCertVerify bool              `proxy:"skip-cert-verify,omitempty"`
	NameCertVerify string            `proxy:"name-cert-verify,omitempty"`
	Fingerprint    string            `proxy:"fingerprint,omitempty"`
	Certificate    string            `proxy:"certificate,omitempty"`
	PrivateKey     string            `proxy:"private-key,omitempty"`
	Headers        map[string]string `proxy:"headers,omitempty"`
	// Path is appended to the CONNECT target (ported from TPBox-ForAndroid).
	// e.g. path: "@混淆" -> "CONNECT example.com:443@混淆 HTTP/1.1"
	Path string `proxy:"path,omitempty"`
	// DelHost drops the default Host header (ported from TPBox-ForAndroid).
	// Ineffective if headers already contains Host. YAML/JSON aliases
	// del-host and del_host both work via the decoder KeyReplacer.
	DelHost bool `proxy:"del-host,omitempty"`
}

// StreamConnContext implements C.ProxyAdapter
func (h *Http) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	if h.tlsConfig != nil {
		cc := tls.Client(c, h.tlsConfig)
		err := cc.HandshakeContext(ctx)
		c = cc
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", h.addr, err)
		}
	}

	if err := h.shakeHandContext(ctx, c, metadata); err != nil {
		return nil, err
	}
	return c, nil
}

// DialContext implements C.ProxyAdapter
func (h *Http) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := h.dialer.DialContext(ctx, "tcp", h.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", h.addr, err)
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = h.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, h), nil
}

// ProxyInfo implements C.ProxyAdapter
func (h *Http) ProxyInfo() C.ProxyInfo {
	info := h.Base.ProxyInfo()
	info.DialerProxy = h.option.DialerProxy
	return info
}

func (h *Http) shakeHandContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (err error) {
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}

	addr := metadata.RemoteAddress()
	connectTarget := addr
	if h.option.Path != "" {
		// TPBox: CONNECT <host:port><path> HTTP/1.1
		// path "/foo"  -> CONNECT example.com:443/foo HTTP/1.1
		// path "@混淆" -> CONNECT example.com:443@混淆 HTTP/1.1
		connectTarget = addr + h.option.Path
	}
	HeaderString := "CONNECT " + connectTarget + " HTTP/1.1\r\n"
	tempHeaders := map[string]string{
		"Host":             addr,
		"User-Agent":       "Go-http-client/1.1",
		"Proxy-Connection": "Keep-Alive",
	}

	customHost := false
	customUA := false
	for key, value := range h.option.Headers {
		switch {
		// With-At: ported from the `with-at` branch of PuerNya/sing (the sing-box
		// dependency lib). Rewrites the CONNECT line into
		// "CONNECT <target>@<free-flow-host> HTTP/1.1" so that the carrier
		// zero-rating (免流) check or the upstream proxy's domain whitelist sees
		// the free-flow domain (e.g. China Unicom DingTalk direct free-flow),
		// while the actual target is still carried in front of the '@'.
		// The header itself is consumed here and is NOT sent to the proxy.
		// Skipped when Path is set: Path is the dedicated TPBox field and wins.
		case strings.EqualFold(key, "With-At") && value != "":
			if h.option.Path == "" {
				HeaderString = "CONNECT " + addr + "@" + value + " HTTP/1.1\r\n"
			}
		// Baidu-Direct: also from PuerNya/sing (baidu-direct branch), the
		// "fake first packet" variant used by Baidu direct free-flow proxies:
		// the space before "HTTP/1.1" is intentionally dropped.
		case strings.EqualFold(key, "Baidu-Direct") && value == "true":
			if h.option.Path == "" {
				HeaderString = "CONNECT " + addr + "HTTP/1.1\r\n"
			}
		default:
			if strings.EqualFold(key, "Host") {
				customHost = true
			}
			if strings.EqualFold(key, "User-Agent") {
				customUA = true
			}
			tempHeaders[key] = value
		}
	}

	// TPBox Del Host: omit the default Host header. A custom Host in headers
	// makes this a no-op, matching TPBox ("如果添加的自定义请求头中包含 Host,
	// Del Host 将无效").
	//
	// Baidu squid (gzdt.baidu.com:443) treats Host or a non-empty User-Agent
	// without X-T5-Auth as ERR_ACCESS_DENIED. The handshake TPBox actually
	// gets 200 on is CONNECT + Proxy-Connection only, so also drop the
	// default User-Agent unless the user set one.
	if h.option.DelHost && !customHost {
		delete(tempHeaders, "Host")
		if !customUA {
			delete(tempHeaders, "User-Agent")
		}
	}

	if h.user != "" && h.pass != "" {
		auth := h.user + ":" + h.pass
		tempHeaders["Proxy-Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	}

	for key, value := range tempHeaders {
		HeaderString += key + ": " + value + "\r\n"
	}

	HeaderString += "\r\n"

	_, err = c.Write([]byte(HeaderString))

	if err != nil {
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(c), nil)

	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	if resp.StatusCode == http.StatusProxyAuthRequired {
		return errors.New("HTTP need auth")
	}

	if resp.StatusCode == http.StatusMethodNotAllowed {
		return errors.New("CONNECT method not allowed by proxy")
	}

	if resp.StatusCode >= http.StatusInternalServerError {
		return errors.New(resp.Status)
	}

	return fmt.Errorf("can not connect remote err code: %d", resp.StatusCode)
}

func NewHttp(option HttpOption) (*Http, error) {
	var tlsConfig *tls.Config
	if option.TLS {
		sni := option.Server
		if option.SNI != "" {
			sni = option.SNI
		}
		var err error
		tlsConfig, err = ca.GetTLSConfig(ca.Option{
			TLSConfig: &tls.Config{
				InsecureSkipVerify: option.SkipCertVerify,
				ServerName:         sni,
			},
			Fingerprint:    option.Fingerprint,
			NameCertVerify: option.NameCertVerify,
			Certificate:    option.Certificate,
			PrivateKey:     option.PrivateKey,
		})
		if err != nil {
			return nil, err
		}
	}

	outbound := &Http{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			Type:         C.Http,
			ProviderName: option.ProviderName,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		user:      option.UserName,
		pass:      option.Password,
		tlsConfig: tlsConfig,
		option:    &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}
