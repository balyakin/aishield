package secrets

import (
	"math"
	"regexp"
	"sort"
	"strings"
)

type PatternConfig struct {
	Name    string `json:"name" yaml:"name"`
	Regex   string `json:"regex" yaml:"regex"`
	Replace string `json:"replace" yaml:"replace"`
}

type HighEntropyConfig struct {
	Enabled    bool    `json:"enabled" yaml:"enabled"`
	MinLength  int     `json:"min_length" yaml:"min_length"`
	MinEntropy float64 `json:"min_entropy" yaml:"min_entropy"`
}

type Options struct {
	Enabled        bool
	HighEntropy    HighEntropyConfig
	CustomPatterns []PatternConfig
	MaskStrings    []string
}

type Masker struct {
	enabled        bool
	patterns       []SecretPattern
	highEntropy    HighEntropyConfig
	customWords    []string
	entropyPattern *regexp.Regexp
}

type SecretPattern struct {
	Name    string
	Regex   *regexp.Regexp
	Replace string
}

type MaskResult struct {
	Value   string
	Counts  map[string]int
	Changed bool
}

type Finding struct {
	Type        string `json:"type"`
	Start       int    `json:"start"`
	End         int    `json:"end"`
	Replacement string `json:"replacement"`
}

type candidate struct {
	Finding
	priority int
}

func NewMasker(options Options) (*Masker, error) {
	patterns := builtinPatterns()
	for _, customPattern := range options.CustomPatterns {
		regex, err := regexp.Compile(customPattern.Regex)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, SecretPattern{
			Name:    customPattern.Name,
			Regex:   regex,
			Replace: customPattern.Replace,
		})
	}

	highEntropy := options.HighEntropy
	if highEntropy.MinLength == 0 {
		highEntropy.MinLength = 32
	}
	if highEntropy.MinEntropy == 0 {
		highEntropy.MinEntropy = 4.5
	}

	return &Masker{
		enabled:        options.Enabled,
		patterns:       patterns,
		highEntropy:    highEntropy,
		customWords:    options.MaskStrings,
		entropyPattern: regexp.MustCompile(`[A-Za-z0-9+/=]{32,}`),
	}, nil
}

func (masker *Masker) Mask(input []byte) []byte {
	result := masker.MaskString(string(input))
	return []byte(result.Value)
}

func (masker *Masker) MaskString(input string) MaskResult {
	if !masker.enabled {
		return MaskResult{
			Value:  input,
			Counts: map[string]int{},
		}
	}

	findings := masker.Findings(input)
	value := applyFindings(input, findings)
	counts := countFindings(findings)

	return MaskResult{
		Value:   value,
		Counts:  counts,
		Changed: value != input,
	}
}

func (masker *Masker) Findings(input string) []Finding {
	if !masker.enabled {
		return nil
	}

	candidates := make([]candidate, 0)
	for _, pattern := range masker.patterns {
		matches := pattern.Regex.FindAllStringIndex(input, -1)
		for _, match := range matches {
			candidates = append(candidates, candidate{
				Finding: Finding{
					Type:        pattern.Name,
					Start:       match[0],
					End:         match[1],
					Replacement: pattern.Replace,
				},
				priority: priorityFor(pattern.Name),
			})
		}
	}

	for _, customWord := range masker.customWords {
		if customWord == "" {
			continue
		}
		start := 0
		for {
			index := strings.Index(input[start:], customWord)
			if index < 0 {
				break
			}
			matchStart := start + index
			matchEnd := matchStart + len(customWord)
			candidates = append(candidates, candidate{
				Finding: Finding{
					Type:        "custom",
					Start:       matchStart,
					End:         matchEnd,
					Replacement: "[MASKED:custom]",
				},
				priority: priorityFor("custom"),
			})
			start = matchEnd
		}
	}

	if masker.highEntropy.Enabled {
		for _, match := range masker.entropyPattern.FindAllStringIndex(input, -1) {
			value := input[match[0]:match[1]]
			if len(value) < masker.highEntropy.MinLength {
				continue
			}
			if calculateEntropy(value) < masker.highEntropy.MinEntropy {
				continue
			}
			candidates = append(candidates, candidate{
				Finding: Finding{
					Type:        "high-entropy",
					Start:       match[0],
					End:         match[1],
					Replacement: "[MASKED:high-entropy]",
				},
				priority: priorityFor("high-entropy"),
			})
		}
	}

	return selectFindings(candidates)
}

func (masker *Masker) maskHighEntropy(input string, counts map[string]int) string {
	return masker.entropyPattern.ReplaceAllStringFunc(input, func(value string) string {
		if len(value) < masker.highEntropy.MinLength {
			return value
		}
		if calculateEntropy(value) < masker.highEntropy.MinEntropy {
			return value
		}
		counts["high-entropy"] = counts["high-entropy"] + 1
		return "[MASKED:high-entropy]"
	})
}

func selectFindings(candidates []candidate) []Finding {
	sort.SliceStable(candidates, func(left int, right int) bool {
		if candidates[left].priority != candidates[right].priority {
			return candidates[left].priority < candidates[right].priority
		}
		leftLength := candidates[left].End - candidates[left].Start
		rightLength := candidates[right].End - candidates[right].Start
		if leftLength != rightLength {
			return leftLength > rightLength
		}
		return candidates[left].Start < candidates[right].Start
	})

	selected := make([]candidate, 0, len(candidates))
	for _, item := range candidates {
		overlaps := false
		for _, existing := range selected {
			if rangesOverlap(item.Start, item.End, existing.Start, existing.End) {
				overlaps = true
				break
			}
		}
		if overlaps {
			continue
		}
		selected = append(selected, item)
	}

	sort.SliceStable(selected, func(left int, right int) bool {
		return selected[left].Start < selected[right].Start
	})

	findings := make([]Finding, 0, len(selected))
	for _, item := range selected {
		findings = append(findings, item.Finding)
	}
	return findings
}

func applyFindings(input string, findings []Finding) string {
	if len(findings) == 0 {
		return input
	}
	var builder strings.Builder
	builder.Grow(len(input))
	offset := 0
	for _, finding := range findings {
		if finding.Start < offset || finding.End > len(input) || finding.Start < 0 || finding.End <= finding.Start {
			continue
		}
		builder.WriteString(input[offset:finding.Start])
		builder.WriteString(finding.Replacement)
		offset = finding.End
	}
	builder.WriteString(input[offset:])
	return builder.String()
}

func countFindings(findings []Finding) map[string]int {
	counts := make(map[string]int)
	for _, finding := range findings {
		counts[finding.Type]++
	}
	return counts
}

func rangesOverlap(leftStart int, leftEnd int, rightStart int, rightEnd int) bool {
	return leftStart < rightEnd && rightStart < leftEnd
}

func priorityFor(name string) int {
	switch name {
	case "private-key":
		return 1
	case "jwt":
		return 2
	case "connection-string":
		return 3
	case "api-key", "aws-key", "aws-secret", "github-token", "custom":
		return 4
	case "high-entropy":
		return 11
	default:
		return 5
	}
}

func builtinPatterns() []SecretPattern {
	return []SecretPattern{
		mustPattern("aws-key", `AKIA[0-9A-Z]{16}`, "[MASKED:aws-key]"),
		mustPattern("aws-secret", `(?i)aws_secret_access_key\s*[=:]\s*\S+`, "[MASKED:aws-secret]"),
		mustPattern("github-token", `gh[pousr]_[A-Za-z0-9_]{36,255}`, "[MASKED:github-token]"),
		mustPattern(
			"api-key",
			`(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[=:]\s*['"]?\S{20,}`,
			"[MASKED:api-key]",
		),
		mustPattern(
			"private-key",
			`(?s)-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----|-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`,
			"[MASKED:private-key]",
		),
		mustPattern("jwt", `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`, "[MASKED:jwt]"),
		mustPattern("connection-string", `(?i)(postgres|mysql|mongodb|redis)://\S+`, "[MASKED:connection-string]"),
	}
}

func BuiltinPatternCount() int {
	return len(builtinPatterns())
}

func mustPattern(name string, pattern string, replace string) SecretPattern {
	return SecretPattern{
		Name:    name,
		Regex:   regexp.MustCompile(pattern),
		Replace: replace,
	}
}

func calculateEntropy(value string) float64 {
	if value == "" {
		return 0
	}

	counts := make(map[rune]int)
	for _, character := range value {
		counts[character] = counts[character] + 1
	}

	length := float64(len(value))
	entropy := 0.0
	for _, count := range counts {
		probability := float64(count) / length
		entropy = entropy - probability*math.Log2(probability)
	}
	return entropy
}
