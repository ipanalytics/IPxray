package model

import "time"

type SubjectType string

const (
	SubjectIP   SubjectType = "ip"
	SubjectCIDR SubjectType = "cidr"
	SubjectASN  SubjectType = "asn"
)

type Confidence string

const (
	ConfidenceHigh     Confidence = "high"
	ConfidenceMedium   Confidence = "medium"
	ConfidenceLow      Confidence = "low"
	ConfidenceConflict Confidence = "conflict"
	ConfidenceUnknown  Confidence = "unknown"
)

type Subject struct {
	Type          SubjectType `json:"type"`
	Value         string      `json:"value"`
	MatchedPrefix string      `json:"matched_prefix,omitempty"`
}

type Evidence struct {
	SubjectType   SubjectType `json:"subject_type"`
	Subject       string      `json:"subject"`
	MatchedPrefix string      `json:"matched_prefix,omitempty"`
	Signal        string      `json:"signal"`
	Value         any         `json:"value"`
	Source        string      `json:"source"`
	SourceType    string      `json:"source_type"`
	OriginFamily  string      `json:"origin_family"`
	Severity      string      `json:"severity"`
	ObservedAt    time.Time   `json:"observed_at"`
	ExpiresAt     *time.Time  `json:"expires_at,omitempty"`
	Provenance    Provenance  `json:"provenance"`
}

type Provenance struct {
	Repo     string `json:"repo"`
	Artifact string `json:"artifact"`
	RecordID string `json:"record_id,omitempty"`
}

type Fact struct {
	Key        string     `json:"key"`
	Value      any        `json:"value"`
	Confidence Confidence `json:"confidence"`
	BasedOn    []string   `json:"based_on"`
	Sources    []string   `json:"sources"`
}

type Finding struct {
	Title      string     `json:"title"`
	Meaning    string     `json:"meaning"`
	Caveat     string     `json:"caveat,omitempty"`
	Confidence Confidence `json:"confidence"`
	Sources    []string   `json:"sources"`
}

type Hint struct {
	Profile string `json:"profile"`
	Signal  string `json:"signal"`
	Action  string `json:"action"`
}

type Report struct {
	Subject         Subject           `json:"subject"`
	Status          string            `json:"status"`
	Facts           []Fact            `json:"facts"`
	Findings        []Finding         `json:"findings"`
	Hints           []Hint            `json:"hints,omitempty"`
	SourceFreshness map[string]string `json:"source_freshness"`
	Confidence      Confidence        `json:"confidence"`
	Sources         []string          `json:"sources"`
}
