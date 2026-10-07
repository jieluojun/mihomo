package tlsmirror

import (
	"context"
	"encoding/binary"
	"testing"
)

func TestTLSMirrorExplicitNonceDirections(t *testing.T) {
	m := newMirrorConn(context.Background(), nil, nil, Config{}, nil, nil, nil, nil)
	t.Cleanup(func() { _ = m.Close() })
	m.tls12Explicit = true
	close(m.explicitReady)
	for _, direction := range []string{"c2s", "s2c"} {
		t.Run(direction, func(t *testing.T) {
			t.Parallel()
			for want := uint64(1); want <= 1000; want++ {
				rec := &record{recordType: recordTypeApplicationData, fragment: make([]byte, 8), inserted: true}
				m.fillExplicitNonce(rec, direction == "c2s")
				if got := binary.BigEndian.Uint64(rec.fragment); got != want {
					t.Fatalf("nonce = %d, want %d", got, want)
				}
			}
		})
	}
}
