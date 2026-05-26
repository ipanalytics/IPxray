package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ipanalytics/ipxray/internal/model"
)

func JSON(w io.Writer, r model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func Text(w io.Writer, r model.Report) error {
	fmt.Fprintf(w, "ipxray %s\n\n", r.Subject.Value)
	fmt.Fprintf(w, "Subject      %s %s", strings.ToUpper(string(r.Subject.Type)), r.Subject.Value)
	if r.Subject.MatchedPrefix != "" {
		fmt.Fprintf(w, "  (matched %s)", r.Subject.MatchedPrefix)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Status       %s\n", strings.ToUpper(r.Status))
	if len(r.Facts) > 0 {
		fmt.Fprintln(w, "\nFacts")
		for _, f := range r.Facts {
			fmt.Fprintf(w, "  - %s: %v (%s) [%s]\n", f.Key, f.Value, f.Confidence, strings.Join(f.Sources, ", "))
		}
	}
	if len(r.Findings) > 0 {
		fmt.Fprintln(w, "\nFindings")
		for _, f := range r.Findings {
			fmt.Fprintf(w, "  - %s - %s (%s)\n", f.Title, f.Meaning, f.Confidence)
			if f.Caveat != "" {
				fmt.Fprintf(w, "    Caveat: %s\n", f.Caveat)
			}
		}
	}
	if len(r.Hints) > 0 {
		fmt.Fprintln(w, "\nOperational hints")
		for _, h := range r.Hints {
			fmt.Fprintf(w, "  - %s: %s\n", h.Signal, h.Action)
		}
	}
	if len(r.SourceFreshness) > 0 {
		fmt.Fprintln(w, "\nSource freshness")
		keys := make([]string, 0, len(r.SourceFreshness))
		for k := range r.SourceFreshness {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "  %s %s\n", k, r.SourceFreshness[k])
		}
	}
	if len(r.Sources) > 0 {
		fmt.Fprintf(w, "\nSources      %s\n", strings.Join(r.Sources, ", "))
	}
	fmt.Fprintf(w, "Confidence   %s\n", r.Confidence)
	return nil
}

func Markdown(w io.Writer, r model.Report) error {
	fmt.Fprintf(w, "# ipxray %s\n\n", r.Subject.Value)
	fmt.Fprintf(w, "| Field | Value |\n| --- | --- |\n")
	fmt.Fprintf(w, "| Subject | `%s %s` |\n", r.Subject.Type, r.Subject.Value)
	fmt.Fprintf(w, "| Status | `%s` |\n", r.Status)
	if r.Subject.MatchedPrefix != "" {
		fmt.Fprintf(w, "| Matched prefix | `%s` |\n", r.Subject.MatchedPrefix)
	}
	fmt.Fprintf(w, "| Confidence | `%s` |\n\n", r.Confidence)
	if len(r.Facts) > 0 {
		fmt.Fprintln(w, "## Facts")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Key | Confidence | Sources | Value |")
		fmt.Fprintln(w, "| --- | --- | --- | --- |")
		for _, f := range r.Facts {
			fmt.Fprintf(w, "| `%s` | `%s` | %s | `%v` |\n", f.Key, f.Confidence, strings.Join(f.Sources, ", "), f.Value)
		}
		fmt.Fprintln(w)
	}
	if len(r.Findings) > 0 {
		fmt.Fprintln(w, "## Findings")
		fmt.Fprintln(w)
		for _, f := range r.Findings {
			fmt.Fprintf(w, "- **%s** (%s): %s\n", f.Title, f.Confidence, f.Meaning)
			if f.Caveat != "" {
				fmt.Fprintf(w, "  - Caveat: %s\n", f.Caveat)
			}
		}
		fmt.Fprintln(w)
	}
	return nil
}

func YAML(w io.Writer, r model.Report) error {
	fmt.Fprintf(w, "subject:\n  type: %s\n  value: %s\n", r.Subject.Type, r.Subject.Value)
	if r.Subject.MatchedPrefix != "" {
		fmt.Fprintf(w, "  matched_prefix: %s\n", r.Subject.MatchedPrefix)
	}
	fmt.Fprintf(w, "status: %s\nconfidence: %s\n", r.Status, r.Confidence)
	fmt.Fprintln(w, "facts:")
	for _, f := range r.Facts {
		fmt.Fprintf(w, "  - key: %s\n    confidence: %s\n    sources: [%s]\n    value: %q\n", f.Key, f.Confidence, strings.Join(f.Sources, ", "), fmt.Sprint(f.Value))
	}
	fmt.Fprintln(w, "findings:")
	for _, f := range r.Findings {
		fmt.Fprintf(w, "  - title: %q\n    confidence: %s\n    meaning: %q\n", f.Title, f.Confidence, f.Meaning)
		if f.Caveat != "" {
			fmt.Fprintf(w, "    caveat: %q\n", f.Caveat)
		}
	}
	if len(r.Hints) > 0 {
		fmt.Fprintln(w, "hints:")
		for _, h := range r.Hints {
			fmt.Fprintf(w, "  - profile: %s\n    signal: %s\n    action: %q\n", h.Profile, h.Signal, h.Action)
		}
	}
	return nil
}

func Conflicts(w io.Writer, r model.Report) {
	for _, f := range r.Facts {
		if f.Confidence == model.ConfidenceConflict {
			fmt.Fprintf(w, "Conflict: %s - sources disagree on %v\n", f.Key, f.Value)
			fmt.Fprintln(w, "Interpretation: surface the disagreement and review source provenance before using it operationally.")
		}
	}
}
