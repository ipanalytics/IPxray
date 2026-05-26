package index

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ipanalytics/ipxray/internal/model"
)

type Store struct {
	Evidence []model.Evidence `json:"evidence"`
}

func Load(path string) (*Store, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Store{}, nil
		}
		return nil, err
	}
	var s Store
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func Save(path string, s *Store) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func (s *Store) ForIP(ip netip.Addr) []model.Evidence {
	var out []model.Evidence
	bestBits := -1
	for _, ev := range s.Evidence {
		if ev.SubjectType != model.SubjectIP && ev.SubjectType != model.SubjectCIDR {
			continue
		}
		prefixText := firstNonEmpty(ev.MatchedPrefix, ev.Subject)
		p, err := netip.ParsePrefix(prefixText)
		if err != nil {
			if addr, addrErr := netip.ParseAddr(prefixText); addrErr == nil && addr == ip {
				p = netip.PrefixFrom(addr, addr.BitLen())
			} else {
				continue
			}
		}
		if !p.Contains(ip) {
			continue
		}
		bits := p.Bits()
		if bits > bestBits {
			bestBits = bits
			out = out[:0]
		}
		if bits == bestBits {
			cp := ev
			cp.MatchedPrefix = p.String()
			out = append(out, cp)
		}
	}
	return out
}

func (s *Store) SpecialUseForIP(ip netip.Addr) []model.Evidence {
	var out []model.Evidence
	bestBits := -1
	for _, ev := range s.Evidence {
		if ev.Signal != "special_use" && ev.Signal != "bogon" {
			continue
		}
		p, err := netip.ParsePrefix(firstNonEmpty(ev.MatchedPrefix, ev.Subject))
		if err != nil || !p.Contains(ip) {
			continue
		}
		if p.Bits() > bestBits {
			bestBits = p.Bits()
			out = out[:0]
		}
		if p.Bits() == bestBits {
			cp := ev
			cp.MatchedPrefix = p.String()
			out = append(out, cp)
		}
	}
	return out
}

func (s *Store) ForCIDR(prefix netip.Prefix) []model.Evidence {
	var out []model.Evidence
	for _, ev := range s.Evidence {
		p, err := netip.ParsePrefix(firstNonEmpty(ev.MatchedPrefix, ev.Subject))
		if err != nil {
			continue
		}
		if prefix.Contains(p.Addr()) || p.Contains(prefix.Addr()) {
			out = append(out, ev)
		}
	}
	return out
}

func (s *Store) ForASN(asn uint32) []model.Evidence {
	var out []model.Evidence
	wantA := "AS" + strconv.FormatUint(uint64(asn), 10)
	wantN := strconv.FormatUint(uint64(asn), 10)
	for _, ev := range s.Evidence {
		if ev.SubjectType == model.SubjectASN && (strings.EqualFold(ev.Subject, wantA) || ev.Subject == wantN) {
			out = append(out, ev)
		}
	}
	return out
}

func (s *Store) FilterSources(names []string) *Store {
	if len(names) == 0 {
		return s
	}
	want := map[string]bool{}
	for _, name := range names {
		n := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "_", "-"))
		if n != "" {
			want[n] = true
		}
	}
	out := &Store{}
	for _, ev := range s.Evidence {
		source := strings.ToLower(strings.ReplaceAll(ev.Source, "_", "-"))
		source = strings.ReplaceAll(source, " ", "-")
		if want[source] || want[strings.ToLower(strings.ReplaceAll(ev.Provenance.Repo, "ipanalytics/", ""))] {
			out.Evidence = append(out.Evidence, ev)
		}
	}
	return out
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatUint(uint64(t), 10)
	default:
		return ""
	}
}
