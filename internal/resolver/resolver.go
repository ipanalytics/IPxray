package resolver

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ipanalytics/ipxray/internal/confidence"
	"github.com/ipanalytics/ipxray/internal/explain"
	"github.com/ipanalytics/ipxray/internal/index"
	"github.com/ipanalytics/ipxray/internal/model"
)

func Resolve(store *index.Store, input string) (model.Report, error) {
	input = strings.TrimSpace(input)
	if ip, err := netip.ParseAddr(input); err == nil {
		return resolveIP(store, ip), nil
	}
	if p, err := netip.ParsePrefix(input); err == nil {
		return resolveCIDR(store, p), nil
	}
	if asn, ok := parseASN(input); ok {
		return resolveASN(store, asn), nil
	}
	return model.Report{}, fmt.Errorf("unsupported subject %q: expected IP, CIDR, or ASN", input)
}

func resolveIP(store *index.Store, ip netip.Addr) model.Report {
	if ev := store.SpecialUseForIP(ip); len(ev) > 0 {
		facts := factsFromEvidence(ev)
		return finalize(model.Report{Subject: model.Subject{Type: model.SubjectIP, Value: ip.String(), MatchedPrefix: ev[0].MatchedPrefix}, Status: "special_use", Facts: facts}, ev)
	}
	ev := store.ForIP(ip)
	if len(ev) == 0 {
		return model.Report{Subject: model.Subject{Type: model.SubjectIP, Value: ip.String()}, Status: "no_data", Confidence: model.ConfidenceUnknown, SourceFreshness: map[string]string{}}
	}
	ev = append(ev, asnFallback(store, ev)...)
	facts := factsFromEvidence(ev)
	return finalize(model.Report{Subject: model.Subject{Type: model.SubjectIP, Value: ip.String(), MatchedPrefix: ev[0].MatchedPrefix}, Status: "resolved", Facts: facts}, ev)
}

func resolveCIDR(store *index.Store, p netip.Prefix) model.Report {
	ev := store.ForCIDR(p)
	if len(ev) == 0 {
		return model.Report{Subject: model.Subject{Type: model.SubjectCIDR, Value: p.String()}, Status: "no_data", Confidence: model.ConfidenceUnknown, SourceFreshness: map[string]string{}}
	}
	return finalize(model.Report{Subject: model.Subject{Type: model.SubjectCIDR, Value: p.String(), MatchedPrefix: p.String()}, Status: statusForEvidence(ev), Facts: factsFromEvidence(ev)}, ev)
}

func resolveASN(store *index.Store, asn uint32) model.Report {
	ev := store.ForASN(asn)
	subj := "AS" + strconv.FormatUint(uint64(asn), 10)
	if len(ev) == 0 {
		return model.Report{Subject: model.Subject{Type: model.SubjectASN, Value: subj}, Status: "no_data", Confidence: model.ConfidenceUnknown, SourceFreshness: map[string]string{}}
	}
	return finalize(model.Report{Subject: model.Subject{Type: model.SubjectASN, Value: subj}, Status: "resolved", Facts: factsFromEvidence(ev)}, ev)
}

func factsFromEvidence(evidence []model.Evidence) []model.Fact {
	grouped := map[string][]model.Evidence{}
	for _, ev := range dedupeEvidence(evidence) {
		grouped[claimType(ev.Signal)] = append(grouped[claimType(ev.Signal)], ev)
	}
	var facts []model.Fact
	for claim, evs := range grouped {
		facts = append(facts, model.Fact{
			Key: claim, Value: representativeValue(evs), Confidence: confidence.ForClaim(claim, evs, time.Now().UTC()),
			BasedOn: uniqueSignals(evs), Sources: uniqueSources(evs),
		})
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].Key < facts[j].Key })
	return facts
}

func dedupeEvidence(evidence []model.Evidence) []model.Evidence {
	seen := map[string]bool{}
	var out []model.Evidence
	for _, ev := range evidence {
		key := ev.Source + "\x00" + ev.Signal + "\x00" + ev.MatchedPrefix + "\x00" + semanticValue(ev.Value)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ev)
	}
	return out
}

func semanticValue(v any) string {
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
	return strings.ToLower(strings.TrimSpace(fmt.Sprint(v)))
}

func finalize(r model.Report, evidence []model.Evidence) model.Report {
	r.Findings = explain.Findings(r.Status, r.Facts)
	r.SourceFreshness = freshness(evidence)
	r.Confidence = confidence.Overall(r.Facts)
	r.Sources = uniqueSources(evidence)
	return r
}

func claimType(signal string) string {
	switch signal {
	case "special_use", "bogon":
		return "is_special_use"
	case "rpki_status":
		return "rpki_status"
	case "origin_asn", "asn_org":
		return "origin_asn"
	case "is_tor":
		return "is_tor"
	case "tor_exit":
		return "tor_exit"
	case "hostile_infra_context":
		return "hostile_infra"
	default:
		return signal
	}
}

func representativeValue(evs []model.Evidence) any {
	if len(evs) == 1 {
		return evs[0].Value
	}
	values := make([]any, 0, len(evs))
	for _, ev := range evs {
		values = append(values, ev.Value)
	}
	return values
}

func uniqueSignals(evs []model.Evidence) []string {
	m := map[string]bool{}
	for _, ev := range evs {
		m[ev.Signal] = true
	}
	return sortedKeys(m)
}

func uniqueSources(evs []model.Evidence) []string {
	m := map[string]bool{}
	for _, ev := range evs {
		m[ev.Source] = true
	}
	return sortedKeys(m)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func freshness(evs []model.Evidence) map[string]string {
	out := map[string]string{}
	now := time.Now().UTC()
	for _, ev := range evs {
		if ev.ObservedAt.IsZero() {
			continue
		}
		age := now.Sub(ev.ObservedAt).Round(time.Minute)
		out[ev.Source] = age.String()
	}
	return out
}

func statusForEvidence(evs []model.Evidence) string {
	for _, ev := range evs {
		if ev.Signal == "special_use" || ev.Signal == "bogon" {
			return "special_use"
		}
	}
	return "resolved"
}

func parseASN(s string) (uint32, bool) {
	s = strings.TrimSpace(strings.ToUpper(s))
	s = strings.TrimPrefix(s, "AS")
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err == nil
}

func asnFallback(store *index.Store, evs []model.Evidence) []model.Evidence {
	seen := map[uint32]bool{}
	var out []model.Evidence
	for _, ev := range evs {
		if m, ok := ev.Value.(map[string]any); ok {
			if asn, ok := parseASN(fmt.Sprint(m["asn"])); ok && !seen[asn] {
				seen[asn] = true
				out = append(out, store.ForASN(asn)...)
			}
		}
	}
	return out
}
