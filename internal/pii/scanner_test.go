package pii

import (
	"strings"
	"testing"
)

func TestScannerDetectsEmailAndMasksURLQuery(t *testing.T) {
	scanner := mustScanner(t, Options{Enabled: true, ReplacementMode: ReplacementFake, SecretsEnabled: true})

	result := scanner.Scan("open https://example.test/cb?email=john@example.com&token=sk-123456789012345678901234")

	if result.Counts["EMAIL"] != 1 {
		t.Fatalf("expected one email finding, got %#v", result.Counts)
	}
	if result.Counts["API_KEY"] != 1 {
		t.Fatalf("expected one api key finding, got %#v", result.Counts)
	}
	if strings.Contains(result.MaskedValue, "john@example.com") || strings.Contains(result.MaskedValue, "sk-123") {
		t.Fatalf("masked value leaked original input: %s", result.MaskedValue)
	}
	if !strings.Contains(result.MaskedValue, "?email=") || !strings.Contains(result.MaskedValue, "&token=") {
		t.Fatalf("url structure was not preserved: %s", result.MaskedValue)
	}
	if result.Findings[0].ContextHintMatched == "" {
		t.Fatalf("structured URL finding did not include context hint metadata: %#v", result.Findings[0])
	}
}

func TestRawEmailWithoutContextIsLowConfidence(t *testing.T) {
	scanner := mustScanner(t, Options{Enabled: true, ReplacementMode: ReplacementPlaceholder})

	result := scanner.Scan("john@example.com")

	if result.Counts["EMAIL"] != 1 {
		t.Fatalf("expected one email finding, got %#v", result.Counts)
	}
	if result.Findings[0].Confidence != string(ConfidenceLow) {
		t.Fatalf("expected raw email without context to be low confidence, got %#v", result.Findings[0])
	}
}

func TestURLQueryPercentEncodedOffsets(t *testing.T) {
	scanner := mustScanner(t, Options{Enabled: true, ReplacementMode: ReplacementPlaceholder, SecretsEnabled: true})

	result := scanner.Scan("open https://example.test/cb?email=john%40example.com&next=1")

	if result.Counts["EMAIL"] != 1 {
		t.Fatalf("expected one email finding, got %#v", result.Counts)
	}
	if strings.Contains(result.MaskedValue, "john%40example.com") || strings.Contains(result.MaskedValue, "example.com&next") {
		t.Fatalf("url-encoded email leaked or corrupted following query: %s", result.MaskedValue)
	}
	if !strings.Contains(result.MaskedValue, "&next=1") {
		t.Fatalf("query tail was corrupted: %s", result.MaskedValue)
	}
}

func TestIPv6ShorthandAndMappedAddresses(t *testing.T) {
	scanner := mustScanner(t, Options{Enabled: true, ReplacementMode: ReplacementPlaceholder})

	result := scanner.Scan("loopback ::1 mapped ::ffff:192.0.2.128")

	if result.Counts["IPV6"] != 2 {
		t.Fatalf("expected two IPv6 findings, got %#v (%s)", result.Counts, result.MaskedValue)
	}
}

func TestChecksumValidators(t *testing.T) {
	tests := []struct {
		name    string
		valid   string
		invalid string
		fn      func(string) bool
	}{
		{name: "credit-card", valid: "4111 1111 1111 1111", invalid: "4111 1111 1111 1112", fn: validLuhn},
		{name: "iban", valid: "DE89370400440532013000", invalid: "DE89370400440532013001", fn: validIBAN},
		{name: "nl-bsn", valid: "111222333", invalid: "111222334", fn: validNLBSN},
		{name: "fr-nir", valid: "180010100101845", invalid: "180010100101846", fn: validFRNIR},
		{name: "es-dni", valid: "12345678Z", invalid: "12345678A", fn: validESDNI},
		{name: "es-nie", valid: "X1234567L", invalid: "X1234567A", fn: validESNIE},
		{name: "it-cf", valid: "RSSMRA85M01H501Q", invalid: "RSSMRA85M01H501A", fn: validITCodiceFiscale},
		{name: "pl-pesel", valid: "44051401359", invalid: "44051401358", fn: validPLPESEL},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !test.fn(test.valid) {
				t.Fatalf("expected valid value %q", test.valid)
			}
			if test.fn(test.invalid) {
				t.Fatalf("expected invalid value %q", test.invalid)
			}
		})
	}
}

func TestGermanIBANEmitsDEIBANWhenDEEnabled(t *testing.T) {
	scanner := mustScanner(t, Options{
		Enabled:         true,
		ReplacementMode: ReplacementPlaceholder,
		Countries:       []string{"generic", "DE"},
		EntityTypes:     []string{"IBAN"},
	})

	result := scanner.Scan("iban DE89370400440532013000")

	if result.Counts["DE_IBAN"] != 1 || result.Counts["IBAN"] != 0 {
		t.Fatalf("expected German IBAN to be emitted as DE_IBAN, got %#v", result.Counts)
	}
}

func TestCountryIDsNeedContextHints(t *testing.T) {
	scanner := mustScanner(t, Options{Enabled: true, ReplacementMode: ReplacementPlaceholder})

	withoutContext := scanner.Scan("value 111222333")
	if withoutContext.Counts["NL_BSN"] != 0 {
		t.Fatalf("ambiguous BSN was counted without context: %#v", withoutContext.Counts)
	}

	withContext := scanner.Scan("bsn: 111222333")
	if withContext.Counts["NL_BSN"] != 1 {
		t.Fatalf("BSN with context was not counted: %#v", withContext.Counts)
	}
	if strings.Contains(withContext.MaskedValue, "111222333") {
		t.Fatalf("masked value leaked BSN: %s", withContext.MaskedValue)
	}
}

func TestStreamScannerDetectsSplitEmail(t *testing.T) {
	scanner := mustScanner(t, Options{Enabled: true, ReplacementMode: ReplacementPlaceholder, StreamBufferBytes: 64})
	stream := NewStreamScanner(scanner)

	_ = stream.ScanChunk("contact john@")
	_ = stream.ScanChunk("example.com")
	result := stream.Flush()

	if result.Counts["EMAIL"] != 1 {
		t.Fatalf("expected split email finding, got %#v", result.Counts)
	}
	if strings.Contains(result.MaskedValue, "john@example.com") {
		t.Fatalf("stream output leaked split email: %s", result.MaskedValue)
	}
}

func TestStreamScannerUsesConfiguredBuffer(t *testing.T) {
	scanner := mustScanner(t, Options{Enabled: true, ReplacementMode: ReplacementPlaceholder, StreamBufferBytes: 128})
	stream := NewStreamScanner(scanner)

	_ = stream.ScanChunk("john@")
	_ = stream.ScanChunk(strings.Repeat("a", 70))
	_ = stream.ScanChunk("example.com")
	result := stream.Flush()

	if result.Counts["EMAIL"] != 1 {
		t.Fatalf("expected split email inside configured buffer, got %#v", result.Counts)
	}
}

func TestEncodedPayloadScanningMasksWholeCandidate(t *testing.T) {
	scanner := mustScanner(t, Options{
		Enabled:          true,
		ReplacementMode:  ReplacementPlaceholder,
		ScanEncoded:      true,
		EncodedMinLength: 8,
	})

	result := scanner.Scan("payload=am9obkBleGFtcGxlLmNvbQ==")

	if result.Counts["EMAIL"] != 1 {
		t.Fatalf("expected encoded email count, got %#v", result.Counts)
	}
	if strings.Contains(result.MaskedValue, "am9obkBleGFtcGxlLmNvbQ") {
		t.Fatalf("encoded payload was not masked as a whole: %s", result.MaskedValue)
	}
	if result.Findings[0].Encoding != "base64" || result.Findings[0].Source != "encoded_payload" {
		t.Fatalf("missing encoded finding metadata: %#v", result.Findings[0])
	}
}

func TestEncodedPayloadCountsMultipleInnerTypes(t *testing.T) {
	scanner := mustScanner(t, Options{
		Enabled:          true,
		ReplacementMode:  ReplacementPlaceholder,
		ScanEncoded:      true,
		EncodedMinLength: 8,
	})

	result := scanner.Scan("payload=ZW1haWw9am9obkBleGFtcGxlLmNvbSBjYXJkPTQxMTExMTExMTExMTExMTE=")

	if result.Counts["EMAIL"] != 1 || result.Counts["CREDIT_CARD"] != 1 {
		t.Fatalf("expected encoded email and card counts, got %#v", result.Counts)
	}
}

func TestFakePhoneKeepsKnownCountryCode(t *testing.T) {
	scanner := mustScanner(t, Options{Enabled: true, ReplacementMode: ReplacementFake})

	us := scanner.Scan("phone +1 555 123 4567")
	if !strings.Contains(us.MaskedValue, "+1 ") {
		t.Fatalf("US country code was not preserved: %s", us.MaskedValue)
	}

	uk := scanner.Scan("phone +44 7911 123456")
	if !strings.Contains(uk.MaskedValue, "+44 ") {
		t.Fatalf("UK country code was not preserved: %s", uk.MaskedValue)
	}
}

func TestSecretLikePIIDisabledWhenSecretsDisabledUnlessExplicit(t *testing.T) {
	implicit := mustScanner(t, Options{Enabled: true, SecretsEnabled: false, ReplacementMode: ReplacementPlaceholder})
	implicitResult := implicit.Scan("token=sk-123456789012345678901234")
	if implicitResult.Counts["API_KEY"] != 0 {
		t.Fatalf("implicit API_KEY should be disabled with secrets disabled: %#v", implicitResult.Counts)
	}

	explicit := mustScanner(t, Options{
		Enabled:         true,
		SecretsEnabled:  false,
		EntityTypes:     []string{"API_KEY"},
		ReplacementMode: ReplacementPlaceholder,
	})
	explicitResult := explicit.Scan("token=sk-123456789012345678901234")
	if explicitResult.Counts["API_KEY"] != 1 {
		t.Fatalf("explicit API_KEY should be active: %#v", explicitResult.Counts)
	}
}

func TestCustomPatternUsesReplacementModeWhenReplacementEmpty(t *testing.T) {
	scanner := mustScanner(t, Options{
		Enabled:         true,
		ReplacementMode: ReplacementHash,
		CustomPatterns: []PatternConfig{{
			Name:  "EMPLOYEE_ID",
			Regex: `\bEMP-[0-9]{5}\b`,
		}},
	})

	result := scanner.Scan("employee EMP-12345")

	if result.Counts["EMPLOYEE_ID"] != 1 {
		t.Fatalf("expected custom finding, got %#v", result.Counts)
	}
	if !strings.Contains(result.MaskedValue, "[PII:EMPLOYEE_ID:") {
		t.Fatalf("custom replacement did not respect hash mode: %s", result.MaskedValue)
	}
}

func TestPrivateKeyBlockIsMaskedAsWholeValue(t *testing.T) {
	scanner := mustScanner(t, Options{Enabled: true, ReplacementMode: ReplacementPlaceholder, SecretsEnabled: true})
	input := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"

	result := scanner.Scan(input)

	if result.Counts["PRIVATE_KEY"] != 1 {
		t.Fatalf("expected private key finding, got %#v", result.Counts)
	}
	if strings.Contains(result.MaskedValue, "MIIEvQIB") || strings.Contains(result.MaskedValue, "END PRIVATE KEY") {
		t.Fatalf("private key block leaked: %s", result.MaskedValue)
	}
}

func mustScanner(t *testing.T, options Options) *Scanner {
	t.Helper()
	scanner, err := NewScanner(options)
	if err != nil {
		t.Fatalf("failed to build scanner: %s", err)
	}
	return scanner
}
