package confidence

import (
	"testing"
	"time"

	"github.com/ipanalytics/ipxray/internal/model"
)

func TestEchoDedupeDoesNotInflateToHigh(t *testing.T) {
	now := time.Now().UTC()
	ev := []model.Evidence{
		{Signal: "origin_asn", Value: "AS64500", Source: "SomeBGPView", OriginFamily: "rir_bgp", MatchedPrefix: "203.0.113.0/24", ObservedAt: now},
		{Signal: "origin_asn", Value: "AS64500", Source: "AnotherBGPView", OriginFamily: "rir_bgp", MatchedPrefix: "203.0.113.0/24", ObservedAt: now},
	}
	if got := ForClaim("derived_context", ev, now); got == model.ConfidenceHigh {
		t.Fatalf("same origin family must not count as independent corroboration: got %s", got)
	}
}

func TestAuthoritativeClaimIsHigh(t *testing.T) {
	ev := []model.Evidence{{Signal: "special_use", Value: "private-use", Source: "BogonForge", OriginFamily: "iana_rfc"}}
	if got := ForClaim("is_special_use", ev, time.Now().UTC()); got != model.ConfidenceHigh {
		t.Fatalf("authoritative source should be high, got %s", got)
	}
}
