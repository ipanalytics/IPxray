package explain

import (
	"fmt"

	"github.com/ipanalytics/ipxray/internal/model"
)

func Findings(status string, facts []model.Fact) []model.Finding {
	if status == "no_data" {
		return []model.Finding{{
			Title:      "No synced evidence",
			Meaning:    "No evidence was found in the local synced datasets for this public subject.",
			Caveat:     "Absence of data is not a statement that the address is unused, safe, or risky.",
			Confidence: model.ConfidenceUnknown,
		}}
	}
	var out []model.Finding
	for _, f := range facts {
		switch f.Key {
		case "is_special_use":
			out = append(out, model.Finding{Title: "Special-use address space", Meaning: "This is not public infrastructure. Do not geolocate, classify, or score it.", Caveat: "Enrichment stops at the special-use finding.", Confidence: f.Confidence, Sources: f.Sources})
		case "origin_asn":
			out = append(out, model.Finding{Title: "Origin ASN context", Meaning: "Routing evidence links this prefix or ASN to public network infrastructure.", Caveat: "ASN ownership describes infrastructure, not the person using traffic from it.", Confidence: f.Confidence, Sources: f.Sources})
		case "rpki_status":
			out = append(out, model.Finding{Title: "Route authorization", Meaning: fmt.Sprintf("RPKI evidence is available for this route: %v.", f.Value), Caveat: "RPKI describes route authorization, not intent or user identity.", Confidence: f.Confidence, Sources: f.Sources})
		case "is_tor":
			out = append(out, model.Finding{Title: "Tor infrastructure", Meaning: "The address or prefix appears in public Tor infrastructure data.", Caveat: "Tor describes traffic source infrastructure, not the person using it.", Confidence: f.Confidence, Sources: f.Sources})
		case "tor_exit":
			out = append(out, model.Finding{Title: "Tor exit infrastructure", Meaning: "The address or prefix appears in public Tor exit data.", Caveat: "Use this for traffic handling policy, not attribution to a person.", Confidence: f.Confidence, Sources: f.Sources})
		case "is_crawler":
			out = append(out, model.Finding{Title: "Crawler infrastructure", Meaning: "The address or prefix appears in crawler infrastructure data.", Caveat: "Apply crawler policy based on the operator signal and your deployment context.", Confidence: f.Confidence, Sources: f.Sources})
		case "operator_geo":
			out = append(out, model.Finding{Title: "Operator geofeed", Meaning: fmt.Sprintf("Operator-published geofeed evidence reports %v.", f.Value), Caveat: "Geofeed data is an operator claim for network location, not a user's location.", Confidence: f.Confidence, Sources: f.Sources})
		case "consensus_geo":
			out = append(out, model.Finding{Title: "Consensus geolocation", Meaning: fmt.Sprintf("GeoIP consensus evidence reports %v.", f.Value), Caveat: "Infrastructure geolocation can differ from user location and routing reality.", Confidence: f.Confidence, Sources: f.Sources})
		case "satellite_geo":
			out = append(out, model.Finding{Title: "Satellite network context", Meaning: "Satellite network infrastructure evidence is present.", Caveat: "Satellite coverage is broad and should be treated as infrastructure context.", Confidence: f.Confidence, Sources: f.Sources})
		case "hostile_infra":
			out = append(out, model.Finding{Title: "Public infrastructure exposure", Meaning: "The prefix appears in public infrastructure or abuse-context datasets.", Caveat: "This is context, not proof of malicious activity or user intent.", Confidence: f.Confidence, Sources: f.Sources})
		case "vpn_context":
			out = append(out, model.Finding{Title: "Aggregate VPN context", Meaning: "The ASN has aggregate VPN-infrastructure exposure in public datasets.", Caveat: "ASN-level context is not IP attribution and not a user-risk verdict.", Confidence: f.Confidence, Sources: f.Sources})
		default:
			out = append(out, model.Finding{Title: "Infrastructure context", Meaning: fmt.Sprintf("Public dataset signal %q is present.", f.Key), Caveat: "Treat this as infrastructure context, not a verdict about a user.", Confidence: f.Confidence, Sources: f.Sources})
		}
	}
	return out
}
