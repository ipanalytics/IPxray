package adapters

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ipanalytics/ipxray/internal/config"
	"github.com/ipanalytics/ipxray/internal/model"
)

func BuildEvidence(home string, sources []config.Source) ([]model.Evidence, error) {
	var all []model.Evidence
	for _, src := range sources {
		dir := filepath.Join(home, "cache", src.Name)
		files, _ := filepath.Glob(filepath.Join(dir, "*"))
		for _, file := range files {
			ev, err := ParseFile(src, file)
			if err != nil {
				return nil, err
			}
			all = append(all, ev...)
		}
	}
	return all, nil
}

func ParseFile(src config.Source, path string) ([]model.Evidence, error) {
	ext := strings.ToLower(filepath.Ext(path))
	base := filepath.Base(path)
	switch {
	case strings.HasSuffix(strings.ToLower(base), ".jsonl.gz"):
		return parseGzipJSONL(src, path)
	case strings.HasSuffix(strings.ToLower(base), ".csv.gz"):
		return parseGzipCSV(src, path)
	case ext == ".json":
		return parseJSON(src, path)
	case ext == ".jsonl":
		return parseJSONL(src, path)
	case ext == ".csv":
		return parseCSV(src, path)
	case strings.HasSuffix(base, ".mmdb"):
		return nil, nil
	default:
		return nil, nil
	}
}

func parseGzipJSONL(src config.Source, path string) ([]model.Evidence, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	return parseJSONLReader(src, path, gz)
}

func parseGzipCSV(src config.Source, path string) ([]model.Evidence, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	return parseCSVReader(src, path, gz)
}

func parseJSONL(src config.Source, path string) ([]model.Evidence, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseJSONLReader(src, path, f)
}

func parseJSONLReader(src config.Source, path string, reader io.Reader) ([]model.Evidence, error) {
	var out []model.Evidence
	sc := bufio.NewScanner(reader)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(text), &row); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		if ev, ok := evidenceFromRow(src, filepath.Base(path), strconv.Itoa(line), row); ok {
			out = append(out, ev...)
		}
	}
	return out, sc.Err()
}

func parseJSON(src config.Source, path string) ([]model.Evidence, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root any
	if err := json.Unmarshal(b, &root); err != nil {
		return nil, err
	}
	switch src.Name {
	case "tor_radar":
		return parseTorRadarJSON(src, filepath.Base(path), root), nil
	case "crawlerscope":
		return parseCrawlerScopeJSON(src, filepath.Base(path), root), nil
	default:
		if rows, ok := root.([]any); ok {
			var out []model.Evidence
			for i, row := range rows {
				if m, ok := row.(map[string]any); ok {
					if ev, ok := evidenceFromRow(src, filepath.Base(path), strconv.Itoa(i+1), m); ok {
						out = append(out, ev...)
					}
				}
			}
			return out, nil
		}
		return nil, nil
	}
}

func parseCSV(src config.Source, path string) ([]model.Evidence, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseCSVReader(src, path, f)
}

func parseCSVReader(src config.Source, path string, reader io.Reader) ([]model.Evidence, error) {
	r := csv.NewReader(reader)
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}
	var out []model.Evidence
	line := 1
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		line++
		row := map[string]any{}
		for i, h := range header {
			if i < len(rec) {
				row[strings.ToLower(strings.TrimSpace(h))] = strings.TrimSpace(rec[i])
			}
		}
		if ev, ok := evidenceFromRow(src, filepath.Base(path), strconv.Itoa(line), row); ok {
			out = append(out, ev...)
		}
	}
	return out, nil
}

func evidenceFromRow(src config.Source, artifact, recordID string, row map[string]any) ([]model.Evidence, bool) {
	now := time.Now().UTC()
	prov := model.Provenance{Repo: src.Repo, Artifact: artifact, RecordID: recordID}
	source := displayName(src.Name)
	switch src.Name {
	case "bogonforge":
		prefix := first(row, "prefix", "cidr", "network")
		if prefix == "" {
			return nil, false
		}
		name := first(row, "name", "policy", "type", "description")
		if name == "" {
			name = "special-use"
		}
		return []model.Evidence{{
			SubjectType: model.SubjectCIDR, Subject: prefix, MatchedPrefix: prefix,
			Signal: "special_use", Value: map[string]any{"name": name, "rfc": first(row, "rfc", "reference")},
			Source: source, SourceType: "special_use_policy", OriginFamily: "iana_rfc", Severity: "context", ObservedAt: now, Provenance: prov,
		}}, true
	case "asnforge":
		prefix := first(row, "prefix", "cidr", "network")
		asn := normalizeASN(first(row, "asn", "origin_asn", "autonomous_system_number"))
		org := first(row, "org", "organization", "name", "asn_name")
		if prefix != "" && asn != "" {
			return []model.Evidence{{
				SubjectType: model.SubjectCIDR, Subject: prefix, MatchedPrefix: prefix,
				Signal: "origin_asn", Value: map[string]any{"asn": asn, "org": org},
				Source: source, SourceType: "prefix_asn", OriginFamily: "rir_bgp", Severity: "info", ObservedAt: now, Provenance: prov,
			}}, true
		}
		if asn != "" && org != "" {
			return []model.Evidence{{
				SubjectType: model.SubjectASN, Subject: asn, Signal: "asn_org", Value: map[string]any{"asn": asn, "org": org},
				Source: source, SourceType: "prefix_asn", OriginFamily: "rir_bgp", Severity: "info", ObservedAt: now, Provenance: prov,
			}}, true
		}
	case "routesentinel":
		prefix := first(row, "prefix", "cidr", "network")
		status := strings.ToLower(first(row, "rpki_status", "status", "validity"))
		asn := normalizeASN(first(row, "asn", "origin_asn"))
		if prefix != "" && status != "" {
			return []model.Evidence{{
				SubjectType: model.SubjectCIDR, Subject: prefix, MatchedPrefix: prefix,
				Signal: "rpki_status", Value: map[string]any{"status": status, "asn": asn},
				Source: source, SourceType: "routing_security", OriginFamily: "rir_bgp", Severity: "notice", ObservedAt: now, Provenance: prov,
			}}, true
		}
	case "ip_knowledge_layer":
		prefix := first(row, "prefix", "cidr", "network", "ip")
		if prefix == "" {
			return nil, false
		}
		signal := first(row, "signal", "classification", "network_type", "type")
		if signal == "" {
			signal = "ip_context"
		}
		return []model.Evidence{{
			SubjectType: model.SubjectCIDR, Subject: prefix, MatchedPrefix: prefix,
			Signal: signal, Value: row, Source: source, SourceType: "unified_ip_knowledge", OriginFamily: "ipanalytics_derived",
			Severity: "context", ObservedAt: now, Provenance: prov,
		}}, true
	case "tor_radar":
		prefix := first(row, "prefix", "cidr", "network", "ip")
		if prefix == "" {
			return nil, false
		}
		exit := parseBool(first(row, "exit", "is_exit", "tor_exit"))
		ev := []model.Evidence{{
			SubjectType: model.SubjectCIDR, Subject: prefix, MatchedPrefix: prefix,
			Signal: "is_tor", Value: map[string]any{"relay": true, "exit": exit},
			Source: source, SourceType: "public_tor_directory", OriginFamily: "tor_directory", Severity: "context", ObservedAt: now, Provenance: prov,
		}}
		if exit {
			ev = append(ev, model.Evidence{
				SubjectType: model.SubjectCIDR, Subject: prefix, MatchedPrefix: prefix,
				Signal: "tor_exit", Value: true,
				Source: source, SourceType: "public_tor_directory", OriginFamily: "tor_directory", Severity: "context", ObservedAt: now, Provenance: prov,
			})
		}
		return ev, true
	case "crawlerscope":
		prefix := first(row, "prefix", "cidr", "network", "ip")
		if prefix == "" {
			return nil, false
		}
		kind := first(row, "crawler", "name", "operator", "type")
		official := parseBool(first(row, "official", "is_official"))
		return []model.Evidence{{
			SubjectType: model.SubjectCIDR, Subject: prefix, MatchedPrefix: prefix,
			Signal: "is_crawler", Value: map[string]any{"name": kind, "official": official},
			Source: source, SourceType: "crawler_ranges", OriginFamily: originForOfficial(official, "crawler_operator", "public_web"), Severity: "context", ObservedAt: now, Provenance: prov,
		}}, true
	case "geoforge":
		prefix := first(row, "prefix", "cidr", "network", "ip")
		country := first(row, "country", "country_code", "iso_country")
		if prefix == "" || country == "" {
			return nil, false
		}
		return []model.Evidence{{
			SubjectType: model.SubjectCIDR, Subject: prefix, MatchedPrefix: prefix,
			Signal: "consensus_geo", Value: strings.ToUpper(country),
			Source: source, SourceType: "geoip_consensus", OriginFamily: "geoip_vendor", Severity: "context", ObservedAt: now, Provenance: prov,
		}}, true
	case "geofeed_harvester":
		prefix := first(row, "prefix", "cidr", "network")
		country := first(row, "country", "country_code")
		if prefix == "" || country == "" {
			return nil, false
		}
		return []model.Evidence{{
			SubjectType: model.SubjectCIDR, Subject: prefix, MatchedPrefix: prefix,
			Signal: "operator_geo", Value: strings.ToUpper(country),
			Source: source, SourceType: "geofeed", OriginFamily: "operator_geofeed", Severity: "context", ObservedAt: now, Provenance: prov,
		}}, true
	case "sat_geoip":
		prefix := first(row, "prefix", "cidr", "network", "ip")
		if prefix == "" {
			return nil, false
		}
		return []model.Evidence{{
			SubjectType: model.SubjectCIDR, Subject: prefix, MatchedPrefix: prefix,
			Signal: "satellite_geo", Value: map[string]any{"satellite": true, "region": first(row, "region", "beam", "coverage")},
			Source: source, SourceType: "satellite_geoip", OriginFamily: "satellite_operator", Severity: "context", ObservedAt: now, Provenance: prov,
		}}, true
	case "blackroute":
		prefix := first(row, "prefix", "cidr", "network", "ip")
		if prefix == "" {
			return nil, false
		}
		return []model.Evidence{{
			SubjectType: model.SubjectCIDR, Subject: prefix, MatchedPrefix: prefix,
			Signal: "hostile_infra_context", Value: map[string]any{"category": first(row, "category", "type", "signal"), "note": first(row, "note", "description")},
			Source: source, SourceType: "hostile_infra", OriginFamily: "public_abuse_infra", Severity: "notice", ObservedAt: now, Provenance: prov,
		}}, true
	case "vpn_lab":
		asn := normalizeASN(first(row, "asn", "origin_asn"))
		if asn == "" {
			return nil, false
		}
		return []model.Evidence{{
			SubjectType: model.SubjectASN, Subject: asn,
			Signal: "vpn_context", Value: map[string]any{"asn": asn, "exposure": first(row, "exposure", "signal", "category", "observed_records_bucket"), "providers": first(row, "provider_count"), "countries": first(row, "country_count")},
			Source: source, SourceType: "vpn_aggregate", OriginFamily: "vpn_aggregate_public", Severity: "context", ObservedAt: now, Provenance: prov,
		}}, true
	}
	return nil, false
}

func parseTorRadarJSON(src config.Source, artifact string, root any) []model.Evidence {
	doc, ok := root.(map[string]any)
	if !ok {
		return nil
	}
	relays, ok := doc["relays"].([]any)
	if !ok {
		return nil
	}
	observed := parseTime(first(doc, "generatedAt", "generated_at"))
	var out []model.Evidence
	for i, item := range relays {
		relay, ok := item.(map[string]any)
		if !ok {
			continue
		}
		exit := strings.EqualFold(first(relay, "role"), "exit") || containsStringArray(relay["flags"], "Exit")
		for _, ip := range stringArray(relay["ips"]) {
			out = append(out, model.Evidence{
				SubjectType: model.SubjectIP, Subject: ip, MatchedPrefix: ip,
				Signal: "is_tor", Value: map[string]any{"relay": true, "exit": exit, "asn": first(relay, "asn"), "country": first(relay, "country")},
				Source: displayName(src.Name), SourceType: "public_tor_directory", OriginFamily: "tor_directory", Severity: "context", ObservedAt: observed,
				Provenance: model.Provenance{Repo: src.Repo, Artifact: artifact, RecordID: strconv.Itoa(i + 1)},
			})
			if exit {
				out = append(out, model.Evidence{
					SubjectType: model.SubjectIP, Subject: ip, MatchedPrefix: ip, Signal: "tor_exit", Value: true,
					Source: displayName(src.Name), SourceType: "public_tor_directory", OriginFamily: "tor_directory", Severity: "context", ObservedAt: observed,
					Provenance: model.Provenance{Repo: src.Repo, Artifact: artifact, RecordID: strconv.Itoa(i + 1)},
				})
			}
		}
	}
	return out
}

func parseCrawlerScopeJSON(src config.Source, artifact string, root any) []model.Evidence {
	doc, ok := root.(map[string]any)
	if !ok {
		return nil
	}
	services, ok := doc["services"].([]any)
	if !ok {
		return nil
	}
	observed := parseTime(first(doc, "generatedAt", "generated_at"))
	var out []model.Evidence
	for i, item := range services {
		service, ok := item.(map[string]any)
		if !ok {
			continue
		}
		official := parseBool(first(service, "ipListAuthoritative", "official"))
		for _, prefix := range prefixesFromCrawler(service["prefixes"]) {
			out = append(out, model.Evidence{
				SubjectType: model.SubjectCIDR, Subject: prefix, MatchedPrefix: prefix,
				Signal: "is_crawler", Value: map[string]any{"id": first(service, "id"), "operator": first(service, "operator"), "category": first(service, "category"), "official": official},
				Source: displayName(src.Name), SourceType: "crawler_ranges", OriginFamily: originForOfficial(official, "crawler_operator", "public_web"), Severity: "context", ObservedAt: observed,
				Provenance: model.Provenance{Repo: src.Repo, Artifact: artifact, RecordID: strconv.Itoa(i + 1)},
			})
		}
	}
	return out
}

func first(row map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := row[k]; ok {
			if s := strings.TrimSpace(fmt.Sprint(v)); s != "" && s != "<nil>" {
				return s
			}
		}
	}
	return ""
}

func normalizeASN(s string) string {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "AS") {
		return s
	}
	return "AS" + s
}

func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "t", "true", "yes", "y", "exit":
		return true
	default:
		return false
	}
}

func parseTime(s string) time.Time {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Now().UTC()
}

func stringArray(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s := strings.TrimSpace(fmt.Sprint(item)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func containsStringArray(v any, want string) bool {
	for _, s := range stringArray(v) {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

func prefixesFromCrawler(v any) []string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	var out []string
	out = append(out, stringArray(m["ipv4"])...)
	out = append(out, stringArray(m["ipv6"])...)
	return out
}

func originForOfficial(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

func displayName(name string) string {
	switch name {
	case "asnforge":
		return "ASNforge"
	case "bogonforge":
		return "BogonForge"
	case "routesentinel":
		return "RouteSentinel"
	case "ip_knowledge_layer":
		return "IP-Knowledge-Layer"
	case "tor_radar":
		return "Tor-Radar"
	case "crawlerscope":
		return "CrawlerScope"
	case "geoforge":
		return "GeoForge"
	case "geofeed_harvester":
		return "GeoFeed-Harvester"
	case "sat_geoip":
		return "Sat-geoip"
	case "blackroute":
		return "BlackRoute"
	case "vpn_lab":
		return "VPN-Lab"
	default:
		return name
	}
}
