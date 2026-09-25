package updater

import (
	"fmt"
	"testing"
)

func TestCoreBaseName(t *testing.T) {
	fmt.Println("Core base name =", DefaultCoreUpdater.CoreBaseName())
}

func TestUpdateURLsUseWithAtRelease(t *testing.T) {
	const expectedBase = "https://github.com/jieluojun/mihomo/releases/download/with-at-latest/"
	if baseReleaseURL != expectedBase || baseAlphaURL != expectedBase {
		t.Fatalf("updater base URLs must target the With-At fork: release=%q alpha=%q", baseReleaseURL, baseAlphaURL)
	}
	if versionReleaseURL != expectedBase+"version.txt" || versionAlphaURL != expectedBase+"version.txt" {
		t.Fatalf("updater version URLs must target the With-At fork: release=%q alpha=%q", versionReleaseURL, versionAlphaURL)
	}
}
