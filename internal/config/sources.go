package config

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed sources.yaml
var embeddedSources string

type Source struct {
	Name      string   `json:"name"`
	Repo      string   `json:"repo"`
	Type      string   `json:"type"`
	Artifacts []string `json:"artifacts"`
}

type Registry struct {
	Sources []Source `json:"sources"`
}

func DefaultRegistry() Registry {
	return Registry{Sources: []Source{
		{Name: "asnforge", Repo: "ipanalytics/ASNforge", Type: "prefix_asn", Artifacts: []string{"releases/latest/asnforge-prefixes.jsonl.gz", "releases/latest/asnforge-asn.jsonl.gz", "releases/latest/asnforge.mmdb.gz"}},
		{Name: "bogonforge", Repo: "ipanalytics/BogonForge", Type: "special_use_policy", Artifacts: []string{"releases/latest/bogonforge.jsonl.gz", "releases/latest/bogonforge-asn.jsonl.gz"}},
		{Name: "routesentinel", Repo: "ipanalytics/RouteSentinel", Type: "routing_security", Artifacts: []string{"releases/latest/route-origin-status.csv", "releases/latest/rpki-invalids.csv", "releases/latest/rpki-covered-prefixes.csv"}},
		{Name: "ip_knowledge_layer", Repo: "ipanalytics/IP-Knowledge-Layer", Type: "unified_ip_knowledge", Artifacts: []string{"releases/latest/ip-knowledge.jsonl", "releases/latest/ip-knowledge.csv"}},
		{Name: "tor_radar", Repo: "ipanalytics/Tor-Radar", Type: "tor", Artifacts: []string{"contents/main/data/current/network.json"}},
		{Name: "crawlerscope", Repo: "ipanalytics/CrawlerScope", Type: "crawler", Artifacts: []string{"contents/main/data/current/crawlers.json"}},
		{Name: "geoforge", Repo: "ipanalytics/GeoForge", Type: "geoip_consensus", Artifacts: []string{}},
		{Name: "geofeed_harvester", Repo: "ipanalytics/GeoFeed-Harvester", Type: "geofeed", Artifacts: []string{"releases/latest/geofeed.csv.gz", "releases/latest/geofeed.jsonl.gz"}},
		{Name: "sat_geoip", Repo: "ipanalytics/Sat-geoip", Type: "satellite_geoip", Artifacts: []string{"releases/latest/sat-geoip-prefixes.jsonl", "releases/latest/sat-geoip-prefixes.csv", "releases/latest/sat-geoip.mmdb"}},
		{Name: "blackroute", Repo: "ipanalytics/BlackRoute", Type: "hostile_infra", Artifacts: []string{}},
		{Name: "vpn_lab", Repo: "ipanalytics/VPN-Infrastructure-Intelligence-Lab", Type: "vpn_aggregate", Artifacts: []string{"contents/main/data/atlas_asn_summary.csv"}},
	}}
}

func EmbeddedSourcesYAML() string { return embeddedSources }

func HomeDir() (string, error) {
	if v := os.Getenv("IPXRAY_HOME"); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ipxray"), nil
}

func EnsureLayout(home string) error {
	for _, dir := range []string{"cache", "indexes", "reports"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o755); err != nil {
			return err
		}
	}
	cfg := filepath.Join(home, "config.yaml")
	if _, err := os.Stat(cfg); os.IsNotExist(err) {
		if err := os.WriteFile(cfg, []byte("sources: default\n"), 0o644); err != nil {
			return err
		}
	}
	src := filepath.Join(home, "sources.yaml")
	if _, err := os.Stat(src); os.IsNotExist(err) {
		if err := os.WriteFile(src, []byte(embeddedSources), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func SelectSources(reg Registry, name string) ([]Source, error) {
	if name == "" || name == "all" {
		return reg.Sources, nil
	}
	want := map[string]bool{}
	for _, part := range strings.Split(name, ",") {
		want[strings.TrimSpace(part)] = true
	}
	var out []Source
	for _, s := range reg.Sources {
		if want[s.Name] {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("unknown source %q", name)
	}
	return out, nil
}
