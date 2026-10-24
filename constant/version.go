package constant

import "strings"

var (
	Meta       = true
	Version    = "1.10.0"
	BuildTime  = "unknown time"
	MihomoName = "mihomo"
)

func init() {
	// ldflags -X overwrites Version at link time (Mishka Gradle, this repo's
	// Actions). Normalize after that so APK/binaries show -zero, not -with-at.
	Version = strings.TrimSuffix(Version, "-with-at")
	if !strings.HasSuffix(Version, "-zero") {
		Version += "-zero"
	}
}
