package pii

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Scanner struct {
	options        Options
	customPatterns []compiledPattern
	explicitTypes  map[string]bool
	enabledTypes   map[string]bool
	countries      map[string]bool

	emailRegex      *regexp.Regexp
	phoneRegex      *regexp.Regexp
	ipv4Regex       *regexp.Regexp
	ipv6Regex       *regexp.Regexp
	cardRegex       *regexp.Regexp
	ibanRegex       *regexp.Regexp
	jwtRegex        *regexp.Regexp
	apiKeyRegex     *regexp.Regexp
	privateKeyRegex *regexp.Regexp
	dbConnRegex     *regexp.Regexp
	macRegex        *regexp.Regexp
	nlBSNRegex      *regexp.Regexp
	frNIRRegex      *regexp.Regexp
	esDNIRegex      *regexp.Regexp
	esNIERegex      *regexp.Regexp
	itCFRegex       *regexp.Regexp
	plPESELRegex    *regexp.Regexp
	urlRegex        *regexp.Regexp
	jsonFieldRegex  *regexp.Regexp
	yamlFieldRegex  *regexp.Regexp
	encodedRegex    *regexp.Regexp
	encodedScanner  *Scanner
}

type compiledPattern struct {
	config PatternConfig
	regex  *regexp.Regexp
}

func NewScanner(options Options) (*Scanner, error) {
	normalized := normalizeOptions(options)
	if err := validateOptions(normalized); err != nil {
		return nil, err
	}

	customPatterns := make([]compiledPattern, 0, len(normalized.CustomPatterns))
	for _, pattern := range normalized.CustomPatterns {
		regex, err := regexp.Compile(pattern.Regex)
		if err != nil {
			return nil, fmt.Errorf("pii.custom_patterns[%s].regex: %w", pattern.Name, err)
		}
		customPatterns = append(customPatterns, compiledPattern{config: pattern, regex: regex})
	}

	scanner := &Scanner{
		options:        normalized,
		customPatterns: customPatterns,
		explicitTypes:  stringSet(normalized.EntityTypes),
		enabledTypes:   enabledTypeSet(normalized.EntityTypes),
		countries:      countrySet(normalized.Countries),

		emailRegex:      regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`),
		phoneRegex:      regexp.MustCompile(`\+[1-9][0-9]{0,3}(?:[\s.\-()]?[0-9]){6,14}`),
		ipv4Regex:       regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`),
		ipv6Regex:       regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]+`),
		cardRegex:       regexp.MustCompile(`\b(?:[0-9][ -]?){13,19}\b`),
		ibanRegex:       regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]){10,30}\b`),
		jwtRegex:        regexp.MustCompile(`\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
		apiKeyRegex:     regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{36,255}|AKIA[0-9A-Z]{16})\b`),
		privateKeyRegex: regexp.MustCompile(`(?s)-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----|-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`),
		dbConnRegex:     regexp.MustCompile(`(?i)\b(?:postgres|postgresql|mysql|mongodb|redis)://[^\s'"<>]+`),
		macRegex:        regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`),
		nlBSNRegex:      regexp.MustCompile(`\b[0-9]{8,9}\b`),
		frNIRRegex:      regexp.MustCompile(`\b[12][0-9]{2}(?:0[1-9]|1[0-2])[0-9]{2}[0-9]{3}[0-9]{3}[0-9]{2}\b`),
		esDNIRegex:      regexp.MustCompile(`\b[0-9]{8}[A-Za-z]\b`),
		esNIERegex:      regexp.MustCompile(`\b[XYZxyz][0-9]{7}[A-Za-z]\b`),
		itCFRegex:       regexp.MustCompile(`\b[A-Za-z]{6}[0-9]{2}[A-Za-z][0-9]{2}[A-Za-z][0-9]{3}[A-Za-z]\b`),
		plPESELRegex:    regexp.MustCompile(`\b[0-9]{11}\b`),
		urlRegex:        regexp.MustCompile(`https?://[^\s'"<>]+`),
		jsonFieldRegex:  regexp.MustCompile(`(?i)"([a-z0-9_.-]*(?:email|phone|iban|token|api[_-]?key|bsn|nir|dni|nie|pesel|ip|mac)[a-z0-9_.-]*)"\s*:\s*"([^"]*)"`),
		yamlFieldRegex:  regexp.MustCompile(`(?i)\b([a-z0-9_.-]*(?:email|phone|iban|token|api[_-]?key|bsn|nir|dni|nie|pesel|ip|mac)[a-z0-9_.-]*)\b\s*[:=]\s*['"]?([^'"\s,}]+)`),
		encodedRegex:    regexp.MustCompile(`[A-Za-z0-9+/_-]{8,}={0,2}`),
	}
	if normalized.ScanEncoded {
		nestedOptions := normalized
		nestedOptions.ScanEncoded = false
		nestedScanner, err := NewScanner(nestedOptions)
		if err != nil {
			return nil, err
		}
		scanner.encodedScanner = nestedScanner
	}
	return scanner, nil
}

func (scanner *Scanner) Scan(input string) ScanResult {
	if scanner == nil || !scanner.options.Enabled {
		return ScanResult{MaskedValue: input, Counts: map[string]int{}}
	}

	scanInput := input
	metadata := map[string]interface{}{}
	if len(scanInput) > scanner.options.MaxScanBytes {
		scanInput = validPrefix(scanInput, scanner.options.MaxScanBytes)
		metadata["truncated"] = true
	}

	findings := scanner.Findings(scanInput)
	maskedPrefix := ApplyFindings(scanInput, findings)
	if len(scanInput) < len(input) {
		maskedPrefix += input[len(scanInput):]
	}
	counts := countFindings(findings)
	if composite(counts) {
		metadata["composite_pii"] = true
	}
	if len(metadata) == 0 {
		metadata = nil
	}
	return ScanResult{
		MaskedValue: maskedPrefix,
		Changed:     maskedPrefix != input,
		Counts:      counts,
		Findings:    findings,
		Metadata:    metadata,
	}
}

func (scanner *Scanner) Findings(input string) []Finding {
	if scanner == nil || !scanner.options.Enabled {
		return nil
	}

	if len(input) > scanner.options.MaxScanBytes {
		input = validPrefix(input, scanner.options.MaxScanBytes)
	}
	candidates := make([]candidate, 0)
	scanner.scanURLs(input, &candidates)
	scanner.scanStructured(input, &candidates)
	scanner.scanRaw(input, &candidates)
	scanner.scanEncoded(input, &candidates)
	scanner.scanCustom(input, &candidates)
	selected := selectCandidates(candidates, scanner.options.MaxFindingsPerInput)
	return selected
}

func ApplyFindings(input string, findings []Finding) string {
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

func (scanner *Scanner) scanRaw(input string, candidates *[]candidate) {
	scanner.addRegexCandidates(input, scanner.privateKeyRegex, "PRIVATE_KEY", ConfidenceHigh, "raw_text", "", nil, candidates)
	scanner.addRegexCandidates(input, scanner.dbConnRegex, "DB_CONN_STRING", ConfidenceHigh, "raw_text", "", nil, candidates)
	scanner.addValidatedRegexCandidates(input, scanner.jwtRegex, "JWT_TOKEN", ConfidenceHigh, "raw_text", "", validJWT, candidates)
	scanner.addRegexCandidates(input, scanner.apiKeyRegex, "API_KEY", ConfidenceHigh, "raw_text", "", nil, candidates)
	scanner.addIBANCandidates(input, "raw_text", "", candidates)
	scanner.addValidatedRegexCandidates(input, scanner.cardRegex, "CREDIT_CARD", ConfidenceHigh, "raw_text", "", validLuhn, candidates)

	scanner.addCountryIDCandidates(input, candidates)
	scanner.addEmailCandidates(input, "raw_text", "", candidates)
	scanner.addPhoneCandidates(input, "raw_text", "", candidates)
	scanner.addValidatedRegexCandidates(input, scanner.ipv4Regex, "IPV4", ConfidenceLow, "raw_text", "", validIPv4, candidates)
	scanner.addValidatedRegexCandidates(input, scanner.ipv6Regex, "IPV6", ConfidenceLow, "raw_text", "", validIPv6, candidates)
	scanner.addRegexCandidates(input, scanner.macRegex, "MAC_ADDRESS", ConfidenceLow, "raw_text", "", nil, candidates)
}

func (scanner *Scanner) scanCustom(input string, candidates *[]candidate) {
	for _, pattern := range scanner.customPatterns {
		if !scanner.typeEnabled(pattern.config.Name) {
			continue
		}
		matches := pattern.regex.FindAllStringIndex(input, -1)
		for _, match := range matches {
			hint := ""
			confidence := ConfidenceHigh
			if len(pattern.config.ContextHints) > 0 {
				hint = scanner.contextHint(input, match[0], match[1], pattern.config.ContextHints)
				if hint == "" {
					continue
				}
				confidence = ConfidenceMedium
			}
			original := input[match[0]:match[1]]
			replacement := pattern.config.Replacement
			if replacement == "" {
				replacement = scanner.replacement(pattern.config.Name, original)
			}
			*candidates = append(*candidates, candidate{
				Finding: Finding{
					Type:               pattern.config.Name,
					ReplacementMode:    string(scanner.options.ReplacementMode),
					Confidence:         string(confidence),
					Start:              match[0],
					End:                match[1],
					Replacement:        replacement,
					Source:             "custom_pattern",
					ContextHintMatched: hint,
				},
				priority: priorityFor(pattern.config.Name),
			})
		}
	}
}

func (scanner *Scanner) scanEncoded(input string, candidates *[]candidate) {
	if !scanner.options.ScanEncoded {
		return
	}
	for _, match := range scanner.encodedRegex.FindAllStringIndex(input, -1) {
		value := input[match[0]:match[1]]
		if len(value) < scanner.options.EncodedMinLength {
			continue
		}
		decoded, ok := decodeBase64Candidate(value)
		if !ok || len(decoded) == 0 || len(decoded) > scanner.options.EncodedMaxDecodedBytes {
			continue
		}
		nestedScanner := scanner.encodedScanner
		if nestedScanner == nil {
			continue
		}
		nested := nestedScanner.Scan(string(decoded))
		if len(nested.Findings) == 0 {
			continue
		}
		entityType := nested.Findings[0].Type
		replacement := "[PII:ENCODED:" + HashFragment("ENCODED", value, 12) + "]"
		extraFindings := make([]Finding, 0, len(nested.Findings)-1)
		for _, nestedFinding := range nested.Findings[1:] {
			extraFindings = append(extraFindings, Finding{
				Type:            nestedFinding.Type,
				ReplacementMode: string(scanner.options.ReplacementMode),
				Confidence:      nestedFinding.Confidence,
				Start:           match[0],
				End:             match[1],
				Replacement:     replacement,
				Source:          "encoded_payload",
				Encoding:        "base64",
			})
		}
		*candidates = append(*candidates, candidate{
			Finding: Finding{
				Type:            entityType,
				ReplacementMode: string(scanner.options.ReplacementMode),
				Confidence:      nested.Findings[0].Confidence,
				Start:           match[0],
				End:             match[1],
				Replacement:     replacement,
				Source:          "encoded_payload",
				Encoding:        "base64",
			},
			priority:      priorityFor(entityType),
			extraFindings: extraFindings,
		})
	}
}

func (scanner *Scanner) scanURLs(input string, candidates *[]candidate) {
	if len(input) > scanner.options.MaxStructuredBytes {
		input = validPrefix(input, scanner.options.MaxStructuredBytes)
	}
	for _, match := range scanner.urlRegex.FindAllStringIndex(input, -1) {
		rawURL := input[match[0]:match[1]]
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.RawQuery == "" {
			continue
		}
		queryStart := strings.Index(rawURL, "?")
		if queryStart < 0 {
			continue
		}
		queryOffset := match[0] + queryStart + 1
		position := 0
		for _, part := range strings.Split(parsed.RawQuery, "&") {
			partStart := queryOffset + position
			position += len(part) + 1
			separator := strings.Index(part, "=")
			if separator < 0 {
				continue
			}
			keyRaw := part[:separator]
			valueRaw := part[separator+1:]
			if valueRaw == "" {
				continue
			}
			key, _ := url.QueryUnescape(keyRaw)
			value, _ := url.QueryUnescape(valueRaw)
			valueStart := partStart + separator + 1
			scanner.addURLQueryValue(strings.ToLower(key), value, valueStart, len(valueRaw), "url.query."+strings.ToLower(key), candidates)
		}
	}
}

func (scanner *Scanner) addURLQueryValue(key string, decodedValue string, start int, rawLength int, path string, candidates *[]candidate) {
	if rawLength <= 0 {
		return
	}
	switch {
	case strings.Contains(key, "email"):
		if scanner.emailRegex.MatchString(decodedValue) {
			scanner.addCandidate("EMAIL", ConfidenceHigh, start, start+rawLength, decodedValue, "url_query", key, path, candidates)
		}
	case strings.Contains(key, "phone"):
		if scanner.phoneRegex.MatchString(decodedValue) {
			scanner.addCandidate("PHONE_INTL", ConfidenceHigh, start, start+rawLength, decodedValue, "url_query", key, path, candidates)
		}
	case strings.Contains(key, "iban"):
		if validIBAN(decodedValue) {
			entityType := "IBAN"
			normalized := normalizeIBAN(decodedValue)
			if strings.HasPrefix(normalized, "DE") && scanner.countryEnabled("DE") {
				entityType = "DE_IBAN"
			}
			scanner.addCandidate(entityType, ConfidenceHigh, start, start+rawLength, decodedValue, "url_query", key, path, candidates)
		}
	default:
		scanner.addStructuredValue(key, decodedValue, start, rawLength, "url_query", path, candidates)
	}
}

func (scanner *Scanner) scanStructured(input string, candidates *[]candidate) {
	if len(input) > scanner.options.MaxStructuredBytes {
		input = validPrefix(input, scanner.options.MaxStructuredBytes)
	}
	for _, match := range scanner.jsonFieldRegex.FindAllStringSubmatchIndex(input, -1) {
		key := strings.ToLower(input[match[2]:match[3]])
		value := input[match[4]:match[5]]
		scanner.addStructuredValue(key, value, match[4], len(value), "json_field", "json."+key, candidates)
	}
	for _, match := range scanner.yamlFieldRegex.FindAllStringSubmatchIndex(input, -1) {
		key := strings.ToLower(input[match[2]:match[3]])
		value := input[match[4]:match[5]]
		source := "yaml_field"
		if strings.Contains(key, "_") && strings.ToUpper(key) == key {
			source = "env_assignment"
		}
		scanner.addStructuredValue(key, value, match[4], len(value), source, "yaml."+key, candidates)
	}
}

func (scanner *Scanner) addStructuredValue(key string, value string, start int, rawLength int, source string, path string, candidates *[]candidate) {
	hint := structuredHint(key)
	switch {
	case strings.Contains(key, "email"):
		scanner.addRegexCandidatesAt(value, scanner.emailRegex, "EMAIL", ConfidenceHigh, source, path, hint, start, candidates)
	case strings.Contains(key, "phone"):
		scanner.addRegexCandidatesAt(value, scanner.phoneRegex, "PHONE_INTL", ConfidenceHigh, source, path, hint, start, candidates)
	case strings.Contains(key, "iban"):
		scanner.addIBANCandidatesAt(value, source, path, hint, start, candidates)
	case strings.Contains(key, "api") || strings.Contains(key, "token"):
		if rawLength > 0 && scanner.secretLikeEnabled("API_KEY") {
			scanner.addCandidate("API_KEY", ConfidenceHigh, start, start+rawLength, value, source, hint, path, candidates)
		}
	case strings.Contains(key, "bsn"):
		if validNLBSN(value) {
			scanner.addCandidate("NL_BSN", ConfidenceHigh, start, start+rawLength, value, source, hint, path, candidates)
		}
	case strings.Contains(key, "nir"):
		if validFRNIR(value) {
			scanner.addCandidate("FR_NIR", ConfidenceHigh, start, start+rawLength, value, source, hint, path, candidates)
		}
	case strings.Contains(key, "dni"):
		if validESDNI(value) {
			scanner.addCandidate("ES_DNI", ConfidenceHigh, start, start+rawLength, value, source, hint, path, candidates)
		}
	case strings.Contains(key, "nie"):
		if validESNIE(value) {
			scanner.addCandidate("ES_NIE", ConfidenceHigh, start, start+rawLength, value, source, hint, path, candidates)
		}
	case strings.Contains(key, "pesel"):
		if validPLPESEL(value) {
			scanner.addCandidate("PL_PESEL", ConfidenceHigh, start, start+rawLength, value, source, hint, path, candidates)
		}
	case strings.Contains(key, "ip"):
		if validIPv4(value) {
			scanner.addCandidate("IPV4", ConfidenceHigh, start, start+rawLength, value, source, hint, path, candidates)
		} else if validIPv6(value) {
			scanner.addCandidate("IPV6", ConfidenceHigh, start, start+rawLength, value, source, hint, path, candidates)
		}
	case strings.Contains(key, "mac"):
		if scanner.macRegex.MatchString(value) {
			scanner.addCandidate("MAC_ADDRESS", ConfidenceHigh, start, start+rawLength, value, source, hint, path, candidates)
		}
	}
}

func (scanner *Scanner) addCountryIDCandidates(input string, candidates *[]candidate) {
	for _, match := range scanner.nlBSNRegex.FindAllStringIndex(input, -1) {
		value := input[match[0]:match[1]]
		hint := scanner.contextHint(input, match[0], match[1], []string{"bsn", "burgerservicenummer"})
		if hint != "" && validNLBSN(value) {
			scanner.addCandidate("NL_BSN", ConfidenceMedium, match[0], match[1], value, "raw_text", hint, "", candidates)
		}
	}
	for _, match := range scanner.frNIRRegex.FindAllStringIndex(input, -1) {
		value := input[match[0]:match[1]]
		hint := scanner.contextHint(input, match[0], match[1], []string{"nir", "social security", "securite sociale"})
		if hint != "" && validFRNIR(value) {
			scanner.addCandidate("FR_NIR", ConfidenceMedium, match[0], match[1], value, "raw_text", hint, "", candidates)
		}
	}
	for _, match := range scanner.esDNIRegex.FindAllStringIndex(input, -1) {
		value := input[match[0]:match[1]]
		hint := scanner.contextHint(input, match[0], match[1], []string{"dni"})
		if hint != "" && validESDNI(value) {
			scanner.addCandidate("ES_DNI", ConfidenceMedium, match[0], match[1], value, "raw_text", hint, "", candidates)
		}
	}
	for _, match := range scanner.esNIERegex.FindAllStringIndex(input, -1) {
		value := input[match[0]:match[1]]
		hint := scanner.contextHint(input, match[0], match[1], []string{"nie"})
		if hint != "" && validESNIE(value) {
			scanner.addCandidate("ES_NIE", ConfidenceMedium, match[0], match[1], value, "raw_text", hint, "", candidates)
		}
	}
	for _, match := range scanner.itCFRegex.FindAllStringIndex(input, -1) {
		value := input[match[0]:match[1]]
		if validITCodiceFiscale(value) {
			scanner.addCandidate("IT_CODICE_FISCALE", ConfidenceHigh, match[0], match[1], value, "raw_text", "", "", candidates)
		}
	}
	for _, match := range scanner.plPESELRegex.FindAllStringIndex(input, -1) {
		value := input[match[0]:match[1]]
		hint := scanner.contextHint(input, match[0], match[1], []string{"pesel"})
		if hint != "" && validPLPESEL(value) {
			scanner.addCandidate("PL_PESEL", ConfidenceMedium, match[0], match[1], value, "raw_text", hint, "", candidates)
		}
	}
}

func (scanner *Scanner) addPhoneCandidates(input string, source string, path string, candidates *[]candidate) {
	for _, match := range scanner.phoneRegex.FindAllStringIndex(input, -1) {
		confidence := ConfidenceLow
		hint := scanner.contextHint(input, match[0], match[1], []string{"phone", "tel", "mobile", "contact"})
		if hint != "" {
			confidence = ConfidenceMedium
		}
		scanner.addCandidate("PHONE_INTL", confidence, match[0], match[1], input[match[0]:match[1]], source, hint, path, candidates)
	}
}

func (scanner *Scanner) addEmailCandidates(input string, source string, path string, candidates *[]candidate) {
	for _, match := range scanner.emailRegex.FindAllStringIndex(input, -1) {
		confidence := ConfidenceLow
		hint := scanner.contextHint(input, match[0], match[1], []string{"email", "e-mail", "mail", "contact"})
		if hint != "" {
			confidence = ConfidenceMedium
		}
		scanner.addCandidate("EMAIL", confidence, match[0], match[1], input[match[0]:match[1]], source, hint, path, candidates)
	}
}

func (scanner *Scanner) addIBANCandidates(input string, source string, path string, candidates *[]candidate) {
	scanner.addIBANCandidatesAt(input, source, path, "", 0, candidates)
}

func (scanner *Scanner) addIBANCandidatesAt(input string, source string, path string, hint string, baseOffset int, candidates *[]candidate) {
	for _, match := range scanner.ibanRegex.FindAllStringIndex(input, -1) {
		value := input[match[0]:match[1]]
		if !validIBAN(value) {
			continue
		}
		entityType := "IBAN"
		normalized := normalizeIBAN(value)
		if strings.HasPrefix(normalized, "DE") && scanner.countryEnabled("DE") {
			entityType = "DE_IBAN"
		}
		scanner.addCandidate(entityType, ConfidenceHigh, baseOffset+match[0], baseOffset+match[1], value, source, hint, path, candidates)
	}
}

func (scanner *Scanner) addValidatedRegexCandidates(
	input string,
	regex *regexp.Regexp,
	entityType string,
	confidence Confidence,
	source string,
	path string,
	validator func(string) bool,
	candidates *[]candidate,
) {
	for _, match := range regex.FindAllStringIndex(input, -1) {
		value := input[match[0]:match[1]]
		if validator != nil && !validator(value) {
			continue
		}
		scanner.addCandidate(entityType, confidence, match[0], match[1], value, source, "", path, candidates)
	}
}

func (scanner *Scanner) addRegexCandidates(
	input string,
	regex *regexp.Regexp,
	entityType string,
	confidence Confidence,
	source string,
	path string,
	validator func(string) bool,
	candidates *[]candidate,
) {
	scanner.addRegexCandidatesAt(input, regex, entityType, confidence, source, path, "", 0, candidates)
}

func (scanner *Scanner) addRegexCandidatesAt(
	input string,
	regex *regexp.Regexp,
	entityType string,
	confidence Confidence,
	source string,
	path string,
	hint string,
	baseOffset int,
	candidates *[]candidate,
) {
	for _, match := range regex.FindAllStringIndex(input, -1) {
		value := input[match[0]:match[1]]
		scanner.addCandidate(entityType, confidence, baseOffset+match[0], baseOffset+match[1], value, source, hint, path, candidates)
	}
}

func (scanner *Scanner) addCandidate(entityType string, confidence Confidence, start int, end int, original string, source string, hint string, path string, candidates *[]candidate) {
	if !scanner.typeEnabled(entityType) {
		return
	}
	if isSecretLike(entityType) && !scanner.secretLikeEnabled(entityType) {
		return
	}
	if !scanner.countryAllowsEntity(entityType) {
		return
	}
	replacement := scanner.replacement(entityType, original)
	*candidates = append(*candidates, candidate{
		Finding: Finding{
			Type:               entityType,
			ReplacementMode:    string(scanner.options.ReplacementMode),
			Confidence:         string(confidence),
			Start:              start,
			End:                end,
			Replacement:        replacement,
			Source:             source,
			ContextHintMatched: hint,
			StructuredPath:     path,
		},
		priority: priorityFor(entityType),
	})
}

func (scanner *Scanner) replacement(entityType string, original string) string {
	switch scanner.options.ReplacementMode {
	case ReplacementPlaceholder:
		return "[PII:" + entityType + "]"
	case ReplacementHash:
		return "[PII:" + entityType + ":" + HashFragment(entityType, original, 12) + "]"
	case ReplacementFake:
		return scanner.fakeReplacement(entityType, original)
	default:
		return "[PII:" + entityType + "]"
	}
}

func (scanner *Scanner) fakeReplacement(entityType string, original string) string {
	hash := HashFragment(entityType, original, 12)
	switch entityType {
	case "EMAIL":
		return "user_" + hash[:6] + "@example.com"
	case "API_KEY":
		if strings.HasPrefix(original, "sk-") {
			return "sk-REDACTED-" + hash[:8]
		}
		return "[PII:API_KEY:" + hash + "]"
	case "CREDIT_CARD":
		return "4000 0000 0000 0000"
	case "IPV4":
		bytes := hashBytes(entityType, original)
		return fmt.Sprintf("10.%d.%d.%d", hostByte(bytes[0]), hostByte(bytes[1]), hostByte(bytes[2]))
	case "IBAN", "DE_IBAN":
		normalized := normalizeIBAN(original)
		if len(normalized) >= 4 {
			bodyLength := len(normalized) - 4
			return normalized[:2] + "00" + deterministicAlphaNum(hash, bodyLength)
		}
	case "PHONE_INTL":
		return fakePhone(original)
	}
	return "[PII:" + entityType + ":" + hash + "]"
}

func HashFragment(entityType string, original string, length int) string {
	sum := sha256.Sum256([]byte(entityType + "\x00" + original))
	encoded := hex.EncodeToString(sum[:])
	if length > len(encoded) {
		return encoded
	}
	return encoded[:length]
}

func hashBytes(entityType string, original string) []byte {
	sum := sha256.Sum256([]byte(entityType + "\x00" + original))
	return sum[:]
}

func deterministicAlphaNum(hash string, length int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var builder strings.Builder
	for index := 0; index < length; index++ {
		builder.WriteByte(alphabet[int(hash[index%len(hash)])%len(alphabet)])
	}
	return builder.String()
}

func fakePhone(original string) string {
	if !strings.HasPrefix(original, "+") {
		return "+0000000000"
	}
	digits := onlyDigits(original)
	if digits == "" {
		return "+0000000000"
	}
	codeLength := countryCodeLength(digits)
	return "+" + digits[:codeLength] + " " + strings.Repeat("0", maxInt(6, len(digits)-codeLength))
}

func (scanner *Scanner) contextHint(input string, start int, end int, hints []string) string {
	windowStart := start - scanner.options.ContextWindow
	if windowStart < 0 {
		windowStart = 0
	}
	windowEnd := end + scanner.options.ContextWindow
	if windowEnd > len(input) {
		windowEnd = len(input)
	}
	window := strings.ToLower(input[windowStart:windowEnd])
	for _, hint := range hints {
		normalized := strings.ToLower(hint)
		if normalized != "" && strings.Contains(window, normalized) {
			return hint
		}
	}
	return ""
}

func structuredHint(key string) string {
	normalized := strings.ToLower(key)
	hints := []string{"api_key", "email", "phone", "iban", "token", "bsn", "nir", "dni", "nie", "pesel", "ip", "mac"}
	for _, hint := range hints {
		if strings.Contains(normalized, hint) {
			return hint
		}
	}
	if strings.Contains(normalized, "api-key") || strings.Contains(normalized, "apikey") {
		return "api_key"
	}
	return key
}

func selectCandidates(candidates []candidate, maxFindings int) []Finding {
	sort.SliceStable(candidates, func(left int, right int) bool {
		if candidates[left].priority != candidates[right].priority {
			return candidates[left].priority < candidates[right].priority
		}
		leftConfidence := ConfidenceRank(candidates[left].Confidence)
		rightConfidence := ConfidenceRank(candidates[right].Confidence)
		if leftConfidence != rightConfidence {
			return leftConfidence > rightConfidence
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
		if maxFindings > 0 && len(selected) >= maxFindings {
			break
		}
		if item.Start < 0 || item.End <= item.Start {
			continue
		}
		overlap := false
		for _, existing := range selected {
			if rangesOverlap(item.Start, item.End, existing.Start, existing.End) {
				overlap = true
				break
			}
		}
		if overlap {
			continue
		}
		selected = append(selected, item)
	}

	sort.SliceStable(selected, func(left int, right int) bool {
		return selected[left].Start < selected[right].Start
	})

	findings := make([]Finding, 0, len(selected))
	for _, item := range selected {
		if maxFindings > 0 && len(findings) >= maxFindings {
			break
		}
		findings = append(findings, item.Finding)
		for _, extra := range item.extraFindings {
			if maxFindings > 0 && len(findings) >= maxFindings {
				break
			}
			findings = append(findings, extra)
		}
	}
	return findings
}

func countFindings(findings []Finding) map[string]int {
	counts := make(map[string]int)
	for _, finding := range findings {
		counts[finding.Type]++
	}
	return counts
}

func composite(counts map[string]int) bool {
	types := 0
	for _, count := range counts {
		if count > 0 {
			types++
		}
	}
	return types >= 2
}

func rangesOverlap(leftStart int, leftEnd int, rightStart int, rightEnd int) bool {
	return leftStart < rightEnd && rightStart < leftEnd
}

func priorityFor(entityType string) int {
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

func normalizeOptions(options Options) Options {
	if options.ReplacementMode == "" {
		options.ReplacementMode = ReplacementFake
	}
	if options.ContextWindow == 0 {
		options.ContextWindow = 50
	}
	if options.StreamBufferBytes == 0 {
		options.StreamBufferBytes = 4096
	}
	if options.EncodedMinLength == 0 {
		options.EncodedMinLength = 32
	}
	if options.MaxScanBytes == 0 {
		options.MaxScanBytes = 1048576
	}
	if options.MaxStructuredBytes == 0 {
		options.MaxStructuredBytes = 262144
	}
	if options.EncodedMaxDecodedBytes == 0 {
		options.EncodedMaxDecodedBytes = 65536
	}
	if options.MaxFindingsPerInput == 0 {
		options.MaxFindingsPerInput = 500
	}
	return options
}

func validateOptions(options Options) error {
	switch options.ReplacementMode {
	case ReplacementPlaceholder, ReplacementFake, ReplacementHash:
	default:
		return fmt.Errorf("pii.replacement_mode: invalid value %q", options.ReplacementMode)
	}
	if options.ContextWindow < 0 {
		return fmt.Errorf("pii.context_window must be non-negative")
	}
	if options.StreamBufferBytes <= 0 {
		return fmt.Errorf("pii.stream_buffer_bytes must be positive")
	}
	if options.EncodedMinLength <= 0 {
		return fmt.Errorf("pii.encoded_min_length must be positive")
	}
	if options.MaxScanBytes <= 0 {
		return fmt.Errorf("pii.max_scan_bytes must be positive")
	}
	if options.MaxStructuredBytes <= 0 {
		return fmt.Errorf("pii.max_structured_bytes must be positive")
	}
	if options.EncodedMaxDecodedBytes <= 0 {
		return fmt.Errorf("pii.encoded_max_decoded_bytes must be positive")
	}
	if options.MaxFindingsPerInput <= 0 {
		return fmt.Errorf("pii.max_findings_per_input must be positive")
	}
	allowedCountries := map[string]bool{"generic": true, "NL": true, "DE": true, "FR": true, "ES": true, "IT": true, "PL": true}
	for _, country := range options.Countries {
		if !allowedCountries[country] {
			return fmt.Errorf("pii.countries: invalid country %q", country)
		}
	}
	allowedTypes := stringSet(MandatoryEntityTypes())
	for _, pattern := range options.CustomPatterns {
		allowedTypes[pattern.Name] = true
	}
	for _, entityType := range options.EntityTypes {
		if !allowedTypes[entityType] {
			return fmt.Errorf("pii.entity_types: invalid entity type %q", entityType)
		}
	}
	nameRegex := regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	for _, pattern := range options.CustomPatterns {
		if !nameRegex.MatchString(pattern.Name) {
			return fmt.Errorf("pii.custom_patterns.name: %q must match [A-Z][A-Z0-9_]*", pattern.Name)
		}
	}
	return nil
}

func (scanner *Scanner) typeEnabled(entityType string) bool {
	if entityType == "DE_IBAN" && scanner.explicitTypes["IBAN"] {
		return true
	}
	return len(scanner.enabledTypes) == 0 || scanner.enabledTypes[entityType]
}

func (scanner *Scanner) secretLikeEnabled(entityType string) bool {
	return scanner.options.SecretsEnabled || scanner.explicitTypes[entityType]
}

func (scanner *Scanner) countryEnabled(country string) bool {
	return len(scanner.countries) == 0 || scanner.countries[country]
}

func (scanner *Scanner) countryAllowsEntity(entityType string) bool {
	switch entityType {
	case "NL_BSN":
		return scanner.countryEnabled("NL")
	case "DE_IBAN":
		return scanner.countryEnabled("DE")
	case "FR_NIR":
		return scanner.countryEnabled("FR")
	case "ES_DNI", "ES_NIE":
		return scanner.countryEnabled("ES")
	case "IT_CODICE_FISCALE":
		return scanner.countryEnabled("IT")
	case "PL_PESEL":
		return scanner.countryEnabled("PL")
	default:
		return scanner.countryEnabled("generic")
	}
}

func validPrefix(input string, maxBytes int) string {
	if len(input) <= maxBytes {
		return input
	}
	return input[:validPrefixLength(input, maxBytes)]
}

func validPrefixLength(input string, maxBytes int) int {
	if len(input) <= maxBytes {
		return len(input)
	}
	prefix := input[:maxBytes]
	for !utf8.ValidString(prefix) && len(prefix) > 0 {
		prefix = prefix[:len(prefix)-1]
	}
	return len(prefix)
}

func enabledTypeSet(values []string) map[string]bool {
	if len(values) == 0 {
		return nil
	}
	return stringSet(values)
}

func stringSet(values []string) map[string]bool {
	result := make(map[string]bool)
	for _, value := range values {
		result[value] = true
	}
	return result
}

func countrySet(values []string) map[string]bool {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]bool)
	for _, value := range values {
		result[value] = true
	}
	return result
}

func isSecretLike(entityType string) bool {
	switch entityType {
	case "API_KEY", "PRIVATE_KEY", "DB_CONN_STRING", "JWT_TOKEN":
		return true
	default:
		return false
	}
}

func maxInt(left int, right int) int {
	if left > right {
		return left
	}
	return right
}

func hostByte(value byte) int {
	return int(value%254) + 1
}

func countryCodeLength(digits string) int {
	if len(digits) == 0 {
		return 1
	}
	maxLength := 3
	if len(digits) < maxLength {
		maxLength = len(digits)
	}
	for length := maxLength; length >= 1; length-- {
		if knownCallingCodes[digits[:length]] {
			return length
		}
	}
	return 1
}

var knownCallingCodes = map[string]bool{
	"1": true, "7": true,
	"20": true, "27": true, "30": true, "31": true, "32": true, "33": true, "34": true, "36": true, "39": true,
	"40": true, "41": true, "43": true, "44": true, "45": true, "46": true, "47": true, "48": true, "49": true,
	"51": true, "52": true, "53": true, "54": true, "55": true, "56": true, "57": true, "58": true,
	"60": true, "61": true, "62": true, "63": true, "64": true, "65": true, "66": true,
	"81": true, "82": true, "84": true, "86": true, "90": true, "91": true, "92": true, "93": true, "94": true,
	"95": true, "98": true,
	"212": true, "213": true, "216": true, "218": true, "220": true, "221": true, "222": true, "223": true,
	"224": true, "225": true, "226": true, "227": true, "228": true, "229": true, "230": true, "231": true,
	"232": true, "233": true, "234": true, "235": true, "236": true, "237": true, "238": true, "239": true,
	"240": true, "241": true, "242": true, "243": true, "244": true, "245": true, "246": true, "248": true,
	"249": true, "250": true, "251": true, "252": true, "253": true, "254": true, "255": true, "256": true,
	"257": true, "258": true, "260": true, "261": true, "262": true, "263": true, "264": true, "265": true,
	"266": true, "267": true, "268": true, "269": true, "290": true, "291": true, "297": true, "298": true,
	"299": true, "350": true, "351": true, "352": true, "353": true, "354": true, "355": true, "356": true,
	"357": true, "358": true, "359": true, "370": true, "371": true, "372": true, "373": true, "374": true,
	"375": true, "376": true, "377": true, "378": true, "380": true, "381": true, "382": true, "383": true,
	"385": true, "386": true, "387": true, "389": true, "420": true, "421": true, "423": true,
}

func decodeBase64Candidate(value string) ([]byte, bool) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return decoded, true
		}
	}
	if remainder := len(value) % 4; remainder != 0 {
		padded := value + strings.Repeat("=", 4-remainder)
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
			decoded, err := encoding.DecodeString(padded)
			if err == nil {
				return decoded, true
			}
		}
	}
	return nil, false
}

func isBoundary(input string, index int) bool {
	if index <= 0 || index >= len(input) {
		return true
	}
	left, _ := utf8.DecodeLastRuneInString(input[:index])
	right, _ := utf8.DecodeRuneInString(input[index:])
	return !isWord(left) || !isWord(right)
}

func isWord(value rune) bool {
	return unicode.IsLetter(value) || unicode.IsDigit(value) || value == '_'
}
