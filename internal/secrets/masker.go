package secrets

import (
	"math"
	"regexp"
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

	value := input
	counts := make(map[string]int)
	for _, pattern := range masker.patterns {
		matches := pattern.Regex.FindAllStringIndex(value, -1)
		if len(matches) == 0 {
			continue
		}
		counts[pattern.Name] = counts[pattern.Name] + len(matches)
		value = pattern.Regex.ReplaceAllString(value, pattern.Replace)
	}

	for _, customWord := range masker.customWords {
		if customWord == "" {
			continue
		}
		count := strings.Count(value, customWord)
		if count == 0 {
			continue
		}
		counts["custom"] = counts["custom"] + count
		value = strings.ReplaceAll(value, customWord, "[MASKED:custom]")
	}

	if masker.highEntropy.Enabled {
		value = masker.maskHighEntropy(value, counts)
	}

	return MaskResult{
		Value:   value,
		Counts:  counts,
		Changed: value != input,
	}
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
		mustPattern("private-key", `-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`, "[MASKED:private-key]"),
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
