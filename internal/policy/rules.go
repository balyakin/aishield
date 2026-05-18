package policy

type Decision string

const (
	Allow Decision = "allow"
	Warn  Decision = "warn"
	Block Decision = "block"
)

const (
	SeverityInfo     = "info"
	SeverityWarn     = "warn"
	SeverityCritical = "critical"
)

type Rule struct {
	Name        string        `json:"name" yaml:"name"`
	Description string        `json:"description" yaml:"description"`
	Decision    Decision      `json:"decision" yaml:"decision"`
	Priority    int           `json:"priority" yaml:"priority"`
	Severity    string        `json:"severity" yaml:"severity"`
	Match       MatchCriteria `json:"match" yaml:"match"`
}

type MatchCriteria struct {
	Executables      []string   `json:"executables,omitempty" yaml:"executables"`
	ArgsContain      []string   `json:"args_contain,omitempty" yaml:"args_contain"`
	ArgsRegex        []string   `json:"args_regex,omitempty" yaml:"args_regex"`
	RawRegex         []string   `json:"raw_regex,omitempty" yaml:"raw_regex"`
	FilePaths        []PathRule `json:"file_paths,omitempty" yaml:"file_paths"`
	HasSudo          *bool      `json:"has_sudo,omitempty" yaml:"has_sudo"`
	EnvVarKeys       []string   `json:"env_var_keys,omitempty" yaml:"env_var_keys"`
	PIITypes         []string   `json:"pii_types,omitempty" yaml:"pii_types"`
	MinPIICount      int        `json:"min_pii_count,omitempty" yaml:"min_pii_count"`
	MinPIIConfidence string     `json:"min_pii_confidence,omitempty" yaml:"min_pii_confidence"`
	NetworkEgress    *bool      `json:"network_egress,omitempty" yaml:"network_egress"`
}

type PathRule struct {
	Pattern string `json:"pattern" yaml:"pattern"`
	Action  string `json:"action" yaml:"action"`
}

type EvalResult struct {
	Decision     Decision `json:"decision" yaml:"decision"`
	Rule         string   `json:"rule" yaml:"rule"`
	MatchedRules []string `json:"matched_rules" yaml:"matched_rules"`
	Severity     string   `json:"severity" yaml:"severity"`
	Reason       string   `json:"reason" yaml:"reason"`
}

type PolicyContext struct {
	PIIFindings   []PIIFinding
	NetworkEgress *bool
}

type PIIFinding struct {
	Type       string `json:"type"`
	Confidence string `json:"confidence"`
}
