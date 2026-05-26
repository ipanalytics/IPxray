package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ipanalytics/ipxray/internal/adapters"
	"github.com/ipanalytics/ipxray/internal/config"
	"github.com/ipanalytics/ipxray/internal/fetcher"
	"github.com/ipanalytics/ipxray/internal/index"
	"github.com/ipanalytics/ipxray/internal/output"
	"github.com/ipanalytics/ipxray/internal/policy"
	"github.com/ipanalytics/ipxray/internal/resolver"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ipxray:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	home, err := config.HomeDir()
	if err != nil {
		return err
	}
	switch args[0] {
	case "init":
		return config.EnsureLayout(home)
	case "sync":
		return cmdSync(home, args[1:])
	case "sources":
		return cmdSources(home)
	case "freshness":
		return cmdFreshness(home)
	case "doctor":
		return cmdDoctor(home)
	case "bulk":
		return cmdBulk(home, args[1:])
	case "ip", "cidr", "asn", "explain":
		if len(args) < 2 {
			return fmt.Errorf("%s requires a subject", args[0])
		}
		return cmdLookup(home, args[1:])
	default:
		return cmdLookup(home, args)
	}
}

func cmdSync(home string, args []string) error {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	source := fs.String("source", "all", "source name or all")
	ifStale := fs.String("if-stale", "", "skip sync if sources.lock is fresher than duration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var stale time.Duration
	if *ifStale != "" {
		d, err := time.ParseDuration(*ifStale)
		if err != nil {
			return err
		}
		stale = d
	}
	srcs, err := config.SelectSources(config.DefaultRegistry(), *source)
	if err != nil {
		return err
	}
	if err := fetcher.Sync(home, srcs, stale); err != nil {
		return err
	}
	ev, err := adapters.BuildEvidence(home, srcs)
	if err != nil {
		return err
	}
	return index.Save(filepath.Join(home, "indexes", "evidence.json"), &index.Store{Evidence: ev})
}

func cmdSources(home string) error {
	lock, err := fetcher.LoadLock(home)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SOURCE\tSTATUS\tUPDATED\tARTIFACTS")
	for _, src := range config.DefaultRegistry().Sources {
		status := "not-synced"
		updated := "-"
		artifacts := "-"
		if ls, ok := lock.Sources[src.Name]; ok {
			status = ls.Status
			if status == "" {
				status = "synced"
			}
			updated = ls.UpdatedAt.Format(time.RFC3339)
			artifacts = fmt.Sprint(len(ls.Artifacts))
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", src.Name, status, updated, artifacts)
	}
	return w.Flush()
}

func cmdFreshness(home string) error {
	lock, err := fetcher.LoadLock(home)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SOURCE\tREPO\tTAG\tUPDATED\tARTIFACTS")
	for _, src := range config.DefaultRegistry().Sources {
		ls, ok := lock.Sources[src.Name]
		if !ok {
			fmt.Fprintf(w, "%s\t%s\t-\t-\t0\n", src.Name, src.Repo)
			continue
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n", src.Name, ls.Repo, ls.Tag, ls.UpdatedAt.Format(time.RFC3339), len(ls.Artifacts))
	}
	return w.Flush()
}

func cmdDoctor(home string) error {
	fmt.Println("Home:", home)
	for _, p := range []string{"config.yaml", "sources.yaml", "sources.lock", filepath.Join("indexes", "evidence.json")} {
		full := filepath.Join(home, p)
		if st, err := os.Stat(full); err == nil {
			fmt.Printf("ok   %s (%d bytes)\n", p, st.Size())
		} else {
			fmt.Printf("miss %s\n", p)
		}
	}
	return nil
}

func cmdLookup(home string, args []string) error {
	format := "text"
	profile := ""
	explainConflicts := false
	sourceFilter := ""
	var subject string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			format = "json"
		case "--yaml":
			format = "yaml"
		case "--markdown":
			format = "markdown"
		case "--sources":
			i++
			if i < len(args) {
				sourceFilter = args[i]
			}
		case "--profile":
			i++
			if i < len(args) {
				profile = args[i]
			}
		case "--explain-conflicts":
			explainConflicts = true
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("unknown lookup flag %s", args[i])
			}
			if subject == "" {
				subject = args[i]
			}
		}
	}
	if subject == "" {
		return fmt.Errorf("lookup requires a subject")
	}
	store, err := index.Load(filepath.Join(home, "indexes", "evidence.json"))
	if err != nil {
		return err
	}
	store = store.FilterSources(splitCSV(sourceFilter))
	report, err := resolver.Resolve(store, subject)
	if err != nil {
		return err
	}
	report = policy.Apply(report, profile)
	if explainConflicts {
		output.Conflicts(os.Stdout, report)
	}
	switch format {
	case "json":
		return output.JSON(os.Stdout, report)
	case "yaml":
		return output.YAML(os.Stdout, report)
	case "markdown":
		return output.Markdown(os.Stdout, report)
	default:
		return output.Text(os.Stdout, report)
	}
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func cmdBulk(home string, args []string) error {
	jsonl := false
	profile := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--jsonl", "--json":
			jsonl = true
		case "--profile":
			i++
			if i < len(args) {
				profile = args[i]
			}
		default:
			return fmt.Errorf("unknown bulk flag %s", args[i])
		}
	}
	if !jsonl {
		return fmt.Errorf("bulk currently writes JSONL; pass --jsonl")
	}
	store, err := index.Load(filepath.Join(home, "indexes", "evidence.json"))
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(os.Stdin)
	enc := json.NewEncoder(os.Stdout)
	for sc.Scan() {
		subject := strings.TrimSpace(sc.Text())
		if subject == "" || strings.HasPrefix(subject, "#") {
			continue
		}
		report, err := resolver.Resolve(store, subject)
		if err != nil {
			return err
		}
		report = policy.Apply(report, profile)
		if err := enc.Encode(report); err != nil {
			return err
		}
	}
	return sc.Err()
}

func usage() {
	fmt.Println(strings.TrimSpace(`ipxray - local offline IP intelligence resolver

Usage:
  ipxray init
  ipxray sync [--if-stale 24h] [--source <name>|all]
  ipxray sources
  ipxray freshness
  ipxray doctor
  ipxray <ip|cidr|asn> [--json]
  ipxray <ip|cidr|asn> [--yaml|--markdown] [--profile web|firewall]
  cat ips.txt | ipxray bulk --jsonl
  ipxray ip <ip> [--json]
  ipxray cidr <cidr> [--json]
  ipxray asn <asn> [--json]`))
}
