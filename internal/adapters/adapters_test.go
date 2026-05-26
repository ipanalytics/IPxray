package adapters

import (
	"path/filepath"
	"testing"

	"github.com/ipanalytics/ipxray/internal/config"
)

func TestParseMVPFixtures(t *testing.T) {
	tests := []struct {
		src  config.Source
		file string
		want string
	}{
		{config.Source{Name: "asnforge", Repo: "ipanalytics/ASNforge"}, "../../testdata/asnforge/asn-prefixes.jsonl", "origin_asn"},
		{config.Source{Name: "bogonforge", Repo: "ipanalytics/BogonForge"}, "../../testdata/bogonforge/special-use.jsonl", "special_use"},
		{config.Source{Name: "routesentinel", Repo: "ipanalytics/RouteSentinel"}, "../../testdata/routesentinel/rpki-status.csv", "rpki_status"},
		{config.Source{Name: "ip_knowledge_layer", Repo: "ipanalytics/IP-Knowledge-Layer"}, "../../testdata/ip_knowledge_layer/ip-knowledge.jsonl", "public_dns"},
		{config.Source{Name: "tor_radar", Repo: "ipanalytics/Tor-Radar"}, "../../testdata/tor_radar/tor-prefixes.csv", "is_tor"},
		{config.Source{Name: "crawlerscope", Repo: "ipanalytics/CrawlerScope"}, "../../testdata/crawlerscope/crawler-prefixes.jsonl", "is_crawler"},
		{config.Source{Name: "geoforge", Repo: "ipanalytics/GeoForge"}, "../../testdata/geoforge/geoforge.jsonl", "consensus_geo"},
		{config.Source{Name: "geofeed_harvester", Repo: "ipanalytics/GeoFeed-Harvester"}, "../../testdata/geofeed_harvester/geofeed.csv", "operator_geo"},
		{config.Source{Name: "sat_geoip", Repo: "ipanalytics/Sat-geoip"}, "../../testdata/sat_geoip/satellite.jsonl", "satellite_geo"},
		{config.Source{Name: "blackroute", Repo: "ipanalytics/BlackRoute"}, "../../testdata/blackroute/blackroute.jsonl", "hostile_infra_context"},
		{config.Source{Name: "vpn_lab", Repo: "ipanalytics/VPN-Infrastructure-Intelligence-Lab"}, "../../testdata/vpn_lab/asn-vpn-signals.csv", "vpn_context"},
	}
	for _, tt := range tests {
		ev, err := ParseFile(tt.src, filepath.Clean(tt.file))
		if err != nil {
			t.Fatal(err)
		}
		if len(ev) < 1 {
			t.Fatalf("%s: got %d evidence", tt.src.Name, len(ev))
		}
		if ev[0].Signal != tt.want {
			t.Fatalf("%s: signal = %s", tt.src.Name, ev[0].Signal)
		}
		if ev[0].OriginFamily == "" {
			t.Fatalf("%s: origin family missing", tt.src.Name)
		}
	}
}
