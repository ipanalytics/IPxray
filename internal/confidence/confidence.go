package confidence

import (
	"fmt"
	"strings"
	"time"

	"github.com/ipanalytics/ipxray/internal/model"
)

type Authority string

const (
	AuthorityAuthoritative Authority = "authoritative"
	AuthorityHigh          Authority = "high"
	AuthorityMedium        Authority = "medium"
	AuthorityContextOnly   Authority = "context_only"
	AuthorityNone          Authority = "none"
)

var matrix = map[string]map[string]Authority{
	"is_special_use": {"BogonForge": AuthorityAuthoritative},
	"rpki_status":    {"RouteSentinel": AuthorityAuthoritative},
	"origin_asn":     {"ASNforge": AuthorityAuthoritative},
	"operator_geo":   {"GeoFeed-Harvester": AuthorityHigh},
	"consensus_geo":  {"GeoForge": AuthorityMedium},
	"is_tor":         {"Tor-Radar": AuthorityAuthoritative},
	"tor_exit":       {"Tor-Radar": AuthorityAuthoritative},
	"is_crawler":     {"CrawlerScope": AuthorityHigh},
	"vpn_context":    {"VPN-Lab": AuthorityContextOnly},
	"satellite_geo":  {"Sat-geoip": AuthorityMedium},
	"hostile_infra":  {"BlackRoute": AuthorityHigh},
}

func ForClaim(claimType string, evidence []model.Evidence, now time.Time) model.Confidence {
	if len(evidence) == 0 {
		return model.ConfidenceUnknown
	}
	if hasConflict(evidence) {
		return model.ConfidenceConflict
	}
	origins := map[string]bool{}
	recent := false
	narrow := false
	for _, ev := range evidence {
		sourceName := canonicalSource(ev.Source)
		if matrix[claimType][sourceName] == AuthorityAuthoritative {
			return model.ConfidenceHigh
		}
		if ev.OriginFamily != "" {
			origins[ev.OriginFamily] = true
		}
		if !ev.ObservedAt.IsZero() && now.Sub(ev.ObservedAt) <= 72*time.Hour {
			recent = true
		}
		if isNarrow(ev.MatchedPrefix) || isNarrow(ev.Subject) {
			narrow = true
		}
	}
	if len(origins) >= 2 && recent && narrow {
		return model.ConfidenceHigh
	}
	if len(origins) >= 1 {
		return model.ConfidenceMedium
	}
	return model.ConfidenceLow
}

func Overall(facts []model.Fact) model.Confidence {
	if len(facts) == 0 {
		return model.ConfidenceUnknown
	}
	best := model.ConfidenceUnknown
	for _, f := range facts {
		if f.Confidence == model.ConfidenceConflict {
			return model.ConfidenceConflict
		}
		switch f.Confidence {
		case model.ConfidenceHigh:
			best = model.ConfidenceHigh
		case model.ConfidenceMedium:
			if best != model.ConfidenceHigh {
				best = model.ConfidenceMedium
			}
		case model.ConfidenceLow:
			if best == model.ConfidenceUnknown {
				best = model.ConfidenceLow
			}
		}
	}
	return best
}

func hasConflict(evidence []model.Evidence) bool {
	seen := map[string]bool{}
	for _, ev := range evidence {
		key := strings.ToLower(strings.TrimSpace(anyString(ev.Value)))
		if key == "" {
			continue
		}
		seen[key] = true
	}
	return len(seen) > 1
}

func anyString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		if m, ok := v.(map[string]any); ok {
			for _, key := range []string{"status", "name", "country"} {
				if val := strings.TrimSpace(fmt.Sprint(m[key])); val != "" && val != "<nil>" {
					return key + "=" + strings.ToLower(val)
				}
			}
			parts := []string{}
			for _, key := range []string{"prefix", "provider", "layer", "source_id", "asn", "org"} {
				if val := strings.TrimSpace(fmt.Sprint(m[key])); val != "" && val != "<nil>" {
					parts = append(parts, key+"="+strings.ToLower(val))
				}
			}
			if len(parts) > 0 {
				return strings.Join(parts, "|")
			}
		}
		return fmt.Sprint(v)
	}
}

func isNarrow(prefix string) bool {
	if strings.Contains(prefix, "/32") || strings.Contains(prefix, "/128") {
		return true
	}
	if strings.Contains(prefix, "/24") || strings.Contains(prefix, "/48") {
		return true
	}
	return false
}

func canonicalSource(s string) string {
	switch strings.ToLower(strings.ReplaceAll(s, "_", "-")) {
	case "asnforge":
		return "ASNforge"
	case "bogonforge":
		return "BogonForge"
	case "routesentinel":
		return "RouteSentinel"
	case "ip-knowledge-layer":
		return "IP-Knowledge-Layer"
	case "tor-radar":
		return "Tor-Radar"
	case "crawlerscope":
		return "CrawlerScope"
	case "geoforge":
		return "GeoForge"
	case "geofeed-harvester":
		return "GeoFeed-Harvester"
	case "vpn-lab":
		return "VPN-Lab"
	case "sat-geoip":
		return "Sat-geoip"
	case "blackroute":
		return "BlackRoute"
	default:
		return s
	}
}
