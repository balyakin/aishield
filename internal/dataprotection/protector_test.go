package dataprotection

import (
	"strings"
	"testing"

	"github.com/balyakin/aishield/internal/pii"
	"github.com/balyakin/aishield/internal/secrets"
)

func TestProcessorMasksSecretAndPIISeparately(t *testing.T) {
	masker, err := secrets.NewMasker(secrets.Options{Enabled: true})
	if err != nil {
		t.Fatalf("failed to build secret masker: %s", err)
	}
	scanner, err := pii.NewScanner(pii.Options{Enabled: true, ReplacementMode: pii.ReplacementPlaceholder, SecretsEnabled: true})
	if err != nil {
		t.Fatalf("failed to build PII scanner: %s", err)
	}
	processor := New(masker, scanner)

	result := processor.ProtectString("AKIAIOSFODNN7EXAMPLE john@example.com")

	if result.SecretCounts["aws-key"] != 1 {
		t.Fatalf("expected aws-key count, got %#v", result.SecretCounts)
	}
	if result.PIICounts["EMAIL"] != 1 {
		t.Fatalf("expected email count, got %#v", result.PIICounts)
	}
	if strings.Contains(result.Value, "AKIAIOSFODNN7EXAMPLE") || strings.Contains(result.Value, "john@example.com") {
		t.Fatalf("masked value leaked sensitive data: %s", result.Value)
	}
}

func TestStreamProcessorDetectsPIIAcrossConfiguredBuffer(t *testing.T) {
	masker, err := secrets.NewMasker(secrets.Options{Enabled: true})
	if err != nil {
		t.Fatalf("failed to build secret masker: %s", err)
	}
	scanner, err := pii.NewScanner(pii.Options{
		Enabled:           true,
		ReplacementMode:   pii.ReplacementPlaceholder,
		StreamBufferBytes: 128,
		SecretsEnabled:    true,
	})
	if err != nil {
		t.Fatalf("failed to build PII scanner: %s", err)
	}
	stream := NewStreamProcessor(New(masker, scanner))

	_ = stream.ProtectChunk("john@")
	_ = stream.ProtectChunk(strings.Repeat("a", 70))
	_ = stream.ProtectChunk("example.com")
	result := stream.Flush()

	if result.PIICounts["EMAIL"] != 1 {
		t.Fatalf("expected split email finding, got %#v", result.PIICounts)
	}
}
