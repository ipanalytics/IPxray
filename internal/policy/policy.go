package policy

import "github.com/ipanalytics/ipxray/internal/model"

var profiles = map[string]map[string]string{
	"web": {
		"is_tor":         "if anonymity is restricted by policy: challenge or rate-limit",
		"tor_exit":       "if anonymity is restricted by policy: challenge or rate-limit",
		"is_crawler":     "apply the configured robots and crawler policy",
		"is_special_use": "block on public edge",
	},
	"firewall": {
		"is_special_use": "drop",
		"bogon":          "drop",
		"is_tor":         "optional block, deployment-dependent",
		"tor_exit":       "optional block, deployment-dependent",
	},
}

func Apply(report model.Report, profile string) model.Report {
	rules, ok := profiles[profile]
	if !ok || profile == "" {
		return report
	}
	for _, fact := range report.Facts {
		if action, ok := rules[fact.Key]; ok {
			report.Hints = append(report.Hints, model.Hint{Profile: profile, Signal: fact.Key, Action: action})
		}
	}
	return report
}

func Names() []string {
	return []string{"web", "firewall"}
}
