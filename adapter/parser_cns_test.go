package adapter

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestParseCnsProxy(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":     "cns-test",
		"type":     "cns",
		"server":   "127.0.0.1",
		"port":     23333,
		"key":      "Meng",
		"password": "secret",
		"flag":     "httpUDP",
		"udp":      true,
		"headers": map[string]any{
			"Host": "camouflage.example",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Type() != C.Cns {
		t.Fatalf("proxy type = %s, want Cns", proxy.Type())
	}
	if !proxy.SupportUDP() {
		t.Fatal("parsed CNS proxy does not advertise UDP support")
	}
}
