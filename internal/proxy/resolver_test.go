package proxy_test

import (
	"testing"

	"github.com/yinkoshield/pinscan/internal/proxy"
)

func TestNewResolverReturnsNilForUnresolvableHost(t *testing.T) {
	t.Parallel()

	// .invalid never resolves (RFC 6761), so the real dialer fails fast and the
	// resolver caches the miss as nil.
	if got := proxy.NewResolver().Cert("pinscan-nonexistent.invalid"); got != nil {
		t.Errorf("Cert for an unresolvable host = %v, want nil", got)
	}
}
