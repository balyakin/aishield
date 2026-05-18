package dataprotection

import (
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/balyakin/aishield/internal/pii"
	"github.com/balyakin/aishield/internal/secrets"
)

type Processor struct {
	secrets           *secrets.Masker
	pii               *pii.Scanner
	streamBufferBytes int
}

type Result struct {
	Value          string
	Changed        bool
	PIICounts      map[string]int
	PIIFindings    []pii.Finding
	SecretCounts   map[string]int
	SecretFindings []secrets.Finding
	Summary        Summary
}

type Summary struct {
	PIITotal             int  `json:"pii_total"`
	SecretTotal          int  `json:"secret_total"`
	CompositePII         bool `json:"composite_pii"`
	Minimized            bool `json:"minimized"`
	OriginalValuesLogged bool `json:"original_values_logged"`
}

type candidate struct {
	start       int
	end         int
	replacement string
	priority    int
	secret      *secrets.Finding
	pii         *pii.Finding
}

const maxCombinedFindings = 1000

func New(secretsMasker *secrets.Masker, piiScanner *pii.Scanner) *Processor {
	streamBufferBytes := 64
	if piiScanner != nil && piiScanner.StreamBufferBytes() > 0 {
		streamBufferBytes = piiScanner.StreamBufferBytes()
	}
	return &Processor{secrets: secretsMasker, pii: piiScanner, streamBufferBytes: streamBufferBytes}
}

func (processor *Processor) ProtectString(input string) Result {
	if processor == nil {
		return Result{
			Value:        input,
			PIICounts:    map[string]int{},
			SecretCounts: map[string]int{},
			Summary: Summary{
				Minimized:            true,
				OriginalValuesLogged: false,
			},
		}
	}

	candidates := make([]candidate, 0)
	if processor.secrets != nil {
		for _, finding := range processor.secrets.Findings(input) {
			item := finding
			candidates = append(candidates, candidate{
				start:       finding.Start,
				end:         finding.End,
				replacement: finding.Replacement,
				priority:    secretPriority(finding.Type),
				secret:      &item,
			})
		}
	}
	if processor.pii != nil {
		for _, finding := range processor.pii.Findings(input) {
			item := finding
			candidates = append(candidates, candidate{
				start:       finding.Start,
				end:         finding.End,
				replacement: finding.Replacement,
				priority:    piiPriority(finding.Type),
				pii:         &item,
			})
		}
	}

	selected := selectCandidates(candidates)
	value := apply(input, selected)
	piiFindings := make([]pii.Finding, 0)
	secretFindings := make([]secrets.Finding, 0)
	for _, item := range selected {
		if item.pii != nil {
			piiFindings = append(piiFindings, *item.pii)
		}
		if item.secret != nil {
			secretFindings = append(secretFindings, *item.secret)
		}
	}
	piiCounts := countPII(piiFindings)
	secretCounts := countSecrets(secretFindings)
	return Result{
		Value:          value,
		Changed:        value != input,
		PIICounts:      piiCounts,
		PIIFindings:    piiFindings,
		SecretCounts:   secretCounts,
		SecretFindings: secretFindings,
		Summary: Summary{
			PIITotal:             total(piiCounts),
			SecretTotal:          total(secretCounts),
			CompositePII:         distinctPositive(piiCounts) >= 2,
			Minimized:            true,
			OriginalValuesLogged: false,
		},
	}
}

func (result Result) Merge(other Result) Result {
	result.PIICounts = mergeCounts(result.PIICounts, other.PIICounts)
	result.SecretCounts = mergeCounts(result.SecretCounts, other.SecretCounts)
	result.PIIFindings = append(result.PIIFindings, other.PIIFindings...)
	result.SecretFindings = append(result.SecretFindings, other.SecretFindings...)
	result.Changed = result.Changed || other.Changed
	result.Summary.PIITotal = total(result.PIICounts)
	result.Summary.SecretTotal = total(result.SecretCounts)
	result.Summary.CompositePII = distinctPositive(result.PIICounts) >= 2
	result.Summary.Minimized = true
	result.Summary.OriginalValuesLogged = false
	return result
}

func EmptyResult(value string) Result {
	return Result{
		Value:        value,
		PIICounts:    map[string]int{},
		SecretCounts: map[string]int{},
		Summary: Summary{
			Minimized:            true,
			OriginalValuesLogged: false,
		},
	}
}

type StreamProcessor struct {
	processor *Processor
	pending   string
	holdBytes int
}

func NewStreamProcessor(processor *Processor) *StreamProcessor {
	holdBytes := 64
	if processor != nil && processor.streamBufferBytes > 0 {
		holdBytes = processor.streamBufferBytes
	}
	return &StreamProcessor{processor: processor, holdBytes: holdBytes}
}

func (stream *StreamProcessor) ProtectChunk(chunk string) Result {
	if stream == nil || stream.processor == nil {
		return EmptyResult(chunk)
	}
	stream.pending += chunk
	if len(stream.pending) <= stream.holdBytes {
		return EmptyResult("")
	}
	emitUntil := len(stream.pending) - stream.holdBytes
	for emitUntil > 0 && !utf8.ValidString(stream.pending[:emitUntil]) {
		emitUntil--
	}
	for {
		result := stream.processor.ProtectString(stream.pending)
		adjusted := false
		for _, finding := range result.PIIFindings {
			if finding.Start < emitUntil && finding.End > emitUntil {
				emitUntil = finding.Start
				adjusted = true
			}
		}
		for _, finding := range result.SecretFindings {
			if finding.Start < emitUntil && finding.End > emitUntil {
				emitUntil = finding.Start
				adjusted = true
			}
		}
		if !adjusted {
			break
		}
	}
	emitted := stream.pending[:emitUntil]
	stream.pending = stream.pending[emitUntil:]
	return stream.processor.ProtectString(emitted)
}

func (stream *StreamProcessor) Flush() Result {
	if stream == nil || stream.processor == nil || stream.pending == "" {
		return EmptyResult("")
	}
	pending := stream.pending
	stream.pending = ""
	return stream.processor.ProtectString(pending)
}

func selectCandidates(candidates []candidate) []candidate {
	sort.SliceStable(candidates, func(left int, right int) bool {
		if candidates[left].priority != candidates[right].priority {
			return candidates[left].priority < candidates[right].priority
		}
		if (candidates[left].secret != nil) != (candidates[right].secret != nil) {
			return candidates[left].secret != nil
		}
		leftLength := candidates[left].end - candidates[left].start
		rightLength := candidates[right].end - candidates[right].start
		if leftLength != rightLength {
			return leftLength > rightLength
		}
		return candidates[left].start < candidates[right].start
	})

	selected := make([]candidate, 0, len(candidates))
	for _, item := range candidates {
		if len(selected) >= maxCombinedFindings {
			break
		}
		if item.start < 0 || item.end <= item.start {
			continue
		}
		overlap := false
		for _, existing := range selected {
			if rangesOverlap(item.start, item.end, existing.start, existing.end) {
				overlap = true
				break
			}
		}
		if !overlap {
			selected = append(selected, item)
		}
	}

	sort.SliceStable(selected, func(left int, right int) bool {
		return selected[left].start < selected[right].start
	})
	return selected
}

func apply(input string, findings []candidate) string {
	if len(findings) == 0 {
		return input
	}
	var builder strings.Builder
	builder.Grow(len(input))
	offset := 0
	for _, finding := range findings {
		if finding.start < offset || finding.end > len(input) {
			continue
		}
		builder.WriteString(input[offset:finding.start])
		builder.WriteString(finding.replacement)
		offset = finding.end
	}
	builder.WriteString(input[offset:])
	return builder.String()
}

func countPII(findings []pii.Finding) map[string]int {
	counts := make(map[string]int)
	for _, finding := range findings {
		counts[finding.Type]++
	}
	return counts
}

func countSecrets(findings []secrets.Finding) map[string]int {
	counts := make(map[string]int)
	for _, finding := range findings {
		counts[finding.Type]++
	}
	return counts
}

func mergeCounts(left map[string]int, right map[string]int) map[string]int {
	result := make(map[string]int)
	for key, value := range left {
		result[key] += value
	}
	for key, value := range right {
		result[key] += value
	}
	return result
}

func total(counts map[string]int) int {
	totalCount := 0
	for _, count := range counts {
		totalCount += count
	}
	return totalCount
}

func distinctPositive(counts map[string]int) int {
	totalCount := 0
	for _, count := range counts {
		if count > 0 {
			totalCount++
		}
	}
	return totalCount
}

func rangesOverlap(leftStart int, leftEnd int, rightStart int, rightEnd int) bool {
	return leftStart < rightEnd && rightStart < leftEnd
}

func secretPriority(name string) int {
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

func piiPriority(entityType string) int {
	switch entityType {
	case "PRIVATE_KEY":
		return 1
	case "JWT_TOKEN":
		return 2
	case "DB_CONN_STRING":
		return 3
	case "API_KEY":
		return 4
	case "IBAN", "DE_IBAN":
		return 5
	case "CREDIT_CARD":
		return 6
	case "NL_BSN", "FR_NIR", "ES_DNI", "ES_NIE", "IT_CODICE_FISCALE", "PL_PESEL":
		return 7
	case "EMAIL":
		return 8
	case "PHONE_INTL":
		return 9
	case "IPV4", "IPV6", "MAC_ADDRESS":
		return 10
	default:
		return 7
	}
}
