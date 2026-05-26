package resolver

import (
	"testing"
	"time"

	"github.com/ipanalytics/ipxray/internal/index"
	"github.com/ipanalytics/ipxray/internal/model"
)

func TestResolveSpecialUse(t *testing.T) {
	store := &index.Store{Evidence: []model.Evidence{{
		SubjectType: model.SubjectCIDR, Subject: "192.168.0.0/16", MatchedPrefix: "192.168.0.0/16",
		Signal: "special_use", Value: "private-use", Source: "BogonForge", OriginFamily: "iana_rfc", ObservedAt: time.Now().UTC(),
	}}}
	r, err := Resolve(store, "192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "special_use" {
		t.Fatalf("status = %s", r.Status)
	}
}

func TestResolveNoData(t *testing.T) {
	r, err := Resolve(&index.Store{}, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "no_data" {
		t.Fatalf("status = %s", r.Status)
	}
}

func TestResolveResolved(t *testing.T) {
	store := &index.Store{Evidence: []model.Evidence{{
		SubjectType: model.SubjectCIDR, Subject: "8.8.8.0/24", MatchedPrefix: "8.8.8.0/24",
		Signal: "origin_asn", Value: map[string]any{"asn": "AS15169", "org": "Google LLC"}, Source: "ASNforge", OriginFamily: "rir_bgp", ObservedAt: time.Now().UTC(),
	}}}
	r, err := Resolve(store, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "resolved" || r.Subject.MatchedPrefix != "8.8.8.0/24" {
		t.Fatalf("unexpected report: %#v", r)
	}
}
