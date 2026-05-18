package pii

type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

type ReplacementMode string

const (
	ReplacementPlaceholder ReplacementMode = "placeholder"
	ReplacementFake        ReplacementMode = "fake"
	ReplacementHash        ReplacementMode = "hash"
)

type PatternConfig struct {
	Name         string   `json:"name" yaml:"name"`
	Regex        string   `json:"regex" yaml:"regex"`
	Replacement  string   `json:"replacement" yaml:"replacement"`
	ContextHints []string `json:"context_hints" yaml:"context_hints"`
}

type Options struct {
	Enabled                bool
	Countries              []string
	EntityTypes            []string
	ReplacementMode        ReplacementMode
	ContextWindow          int
	StreamBufferBytes      int
	ScanEncoded            bool
	EncodedMinLength       int
	MaxScanBytes           int
	MaxStructuredBytes     int
	EncodedMaxDecodedBytes int
	MaxFindingsPerInput    int
	CustomPatterns         []PatternConfig
	SecretsEnabled         bool
}

type ScanResult struct {
	MaskedValue string                 `json:"masked_value"`
	Changed     bool                   `json:"changed"`
	Counts      map[string]int         `json:"counts"`
	Findings    []Finding              `json:"findings"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type Finding struct {
	Type               string `json:"type"`
	ReplacementMode    string `json:"replacement_mode"`
	Confidence         string `json:"confidence"`
	Start              int    `json:"start"`
	End                int    `json:"end"`
	Replacement        string `json:"replacement"`
	Source             string `json:"source,omitempty"`
	Encoding           string `json:"encoding,omitempty"`
	ContextHintMatched string `json:"context_hint_matched,omitempty"`
	StructuredPath     string `json:"structured_path,omitempty"`
}

type candidate struct {
	Finding
	priority      int
	extraFindings []Finding
}

func (scanner *Scanner) StreamBufferBytes() int {
	if scanner == nil {
		return 0
	}
	return scanner.options.StreamBufferBytes
}

func MandatoryEntityTypes() []string {
	return []string{
		"EMAIL",
		"PHONE_INTL",
		"IPV4",
		"IPV6",
		"CREDIT_CARD",
		"IBAN",
		"API_KEY",
		"PRIVATE_KEY",
		"DB_CONN_STRING",
		"JWT_TOKEN",
		"MAC_ADDRESS",
		"NL_BSN",
		"DE_IBAN",
		"FR_NIR",
		"ES_DNI",
		"ES_NIE",
		"IT_CODICE_FISCALE",
		"PL_PESEL",
	}
}

func ConfidenceRank(value string) int {
	switch Confidence(value) {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}
