package fetcher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/ipanalytics/ipxray/internal/config"
)

type Lock struct {
	UpdatedAt time.Time               `json:"updated_at"`
	Sources   map[string]LockedSource `json:"sources"`
}

type LockedSource struct {
	Repo      string            `json:"repo"`
	ReleaseID int64             `json:"release_id"`
	Tag       string            `json:"tag"`
	Status    string            `json:"status"`
	Error     string            `json:"error,omitempty"`
	Artifacts map[string]string `json:"artifacts"`
	UpdatedAt time.Time         `json:"updated_at"`
}

type release struct {
	ID      int64   `json:"id"`
	TagName string  `json:"tag_name"`
	Assets  []asset `json:"assets"`
}

type asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

func LoadLock(home string) (Lock, error) {
	var l Lock
	l.Sources = map[string]LockedSource{}
	b, err := os.ReadFile(filepath.Join(home, "sources.lock"))
	if err != nil {
		if os.IsNotExist(err) {
			return l, nil
		}
		return l, err
	}
	if err := json.Unmarshal(b, &l); err != nil {
		return l, err
	}
	if l.Sources == nil {
		l.Sources = map[string]LockedSource{}
	}
	return l, nil
}

func SaveLock(home string, l Lock) error {
	l.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(home, "sources.lock"), b, 0o644)
}

func Sync(home string, sources []config.Source, ifStale time.Duration) error {
	if err := config.EnsureLayout(home); err != nil {
		return err
	}
	lock, err := LoadLock(home)
	if err != nil {
		return err
	}
	if ifStale > 0 && time.Since(lock.UpdatedAt) < ifStale {
		return nil
	}
	client := &http.Client{Timeout: 60 * time.Second}
	for _, src := range sources {
		prev := lock.Sources[src.Name]
		if prev.Status == "synced" && len(prev.Artifacts) == len(src.Artifacts) && len(src.Artifacts) > 0 && ifStale > 0 && time.Since(prev.UpdatedAt) < ifStale {
			continue
		}
		artifactSHA := map[string]string{}
		releaseSpecs, contentSpecs := splitSpecs(src.Artifacts)
		var rel release
		if len(releaseSpecs) > 0 {
			var err error
			rel, err = latestRelease(client, src.Repo)
			if err != nil {
				if errors.Is(err, errNoLatestRelease) {
					lock.Sources[src.Name] = LockedSource{Repo: src.Repo, Status: "no_release", Error: err.Error(), Artifacts: artifactSHA, UpdatedAt: time.Now().UTC()}
					continue
				}
				return err
			}
			expected, err := releaseChecksums(client, rel)
			if err != nil {
				return err
			}
			for _, spec := range releaseSpecs {
				name := path.Base(spec)
				a, ok := findAsset(rel.Assets, name)
				if !ok {
					return fmt.Errorf("%s release %s missing expected asset %s", src.Name, rel.TagName, name)
				}
				dst := filepath.Join(home, "cache", src.Name, a.Name)
				if err := download(client, a.BrowserDownloadURL, dst); err != nil {
					return err
				}
				sum, err := fileSHA256(dst)
				if err != nil {
					return err
				}
				if want := expected[a.Name]; want != "" && !strings.EqualFold(want, sum) {
					return fmt.Errorf("%s checksum mismatch for %s: got %s want %s", src.Name, a.Name, sum, want)
				}
				artifactSHA[a.Name] = sum
			}
		}
		for _, spec := range contentSpecs {
			name := path.Base(spec)
			url, err := contentURL(src.Repo, spec)
			if err != nil {
				return err
			}
			dst := filepath.Join(home, "cache", src.Name, name)
			if err := download(client, url, dst); err != nil {
				return err
			}
			sum, err := fileSHA256(dst)
			if err != nil {
				return err
			}
			artifactSHA[name] = sum
		}
		status := "synced"
		if len(src.Artifacts) == 0 {
			status = "no_artifacts"
		}
		lock.Sources[src.Name] = LockedSource{Repo: src.Repo, ReleaseID: rel.ID, Tag: rel.TagName, Status: status, Artifacts: artifactSHA, UpdatedAt: time.Now().UTC()}
	}
	return SaveLock(home, lock)
}

func releaseChecksums(client *http.Client, rel release) (map[string]string, error) {
	a, ok := findFirstAsset(rel.Assets, "SHA256SUMS", "sha256sums.txt", "checksums.txt", "bundle-checksums.txt")
	if !ok {
		return map[string]string{}, nil
	}
	req, err := http.NewRequest(http.MethodGet, a.BrowserDownloadURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ipxray")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("download checksums: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		sum := strings.TrimSpace(fields[0])
		name := strings.TrimPrefix(strings.TrimSpace(fields[len(fields)-1]), "*")
		out[path.Base(name)] = sum
	}
	return out, nil
}

var errNoLatestRelease = errors.New("no latest release")

func latestRelease(client *http.Client, repo string) (release, error) {
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return release{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "ipxray")
	resp, err := client.Do(req)
	if err != nil {
		return release{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return release{}, fmt.Errorf("%w for %s", errNoLatestRelease, repo)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return release{}, fmt.Errorf("github latest release %s: %s: %s", repo, resp.Status, strings.TrimSpace(string(body)))
	}
	var rel release
	return rel, json.NewDecoder(resp.Body).Decode(&rel)
}

func findFirstAsset(assets []asset, names ...string) (asset, bool) {
	for _, name := range names {
		if a, ok := findAsset(assets, name); ok {
			return a, true
		}
	}
	return asset{}, false
}

func findAsset(assets []asset, name string) (asset, bool) {
	for _, a := range assets {
		if a.Name == name {
			return a, true
		}
	}
	return asset{}, false
}

func splitSpecs(specs []string) (releaseSpecs, contentSpecs []string) {
	for _, spec := range specs {
		switch {
		case strings.HasPrefix(spec, "contents/"):
			contentSpecs = append(contentSpecs, spec)
		default:
			releaseSpecs = append(releaseSpecs, spec)
		}
	}
	return releaseSpecs, contentSpecs
}

func contentURL(repo, spec string) (string, error) {
	parts := strings.SplitN(strings.TrimPrefix(spec, "contents/"), "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid content artifact spec %q", spec)
	}
	return "https://raw.githubusercontent.com/" + repo + "/" + parts[0] + "/" + parts[1], nil
}

func download(client *http.Client, url, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ipxray")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("download %s: %s", url, resp.Status)
	}
	tmp := dst + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	return os.Rename(tmp, dst)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
