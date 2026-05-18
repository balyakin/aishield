package secrets

import "testing"

func TestMaskAWSKey(t *testing.T) {
	masker := mustMasker(t)
	result := masker.MaskString("key: AKIAIOSFODNN7EXAMPLE")

	if result.Value != "key: [MASKED:aws-key]" {
		t.Fatalf("unexpected masked value: %s", result.Value)
	}
}

func TestMaskGitHubToken(t *testing.T) {
	masker := mustMasker(t)
	result := masker.MaskString("token: ghp_1234567890abcdef1234567890abcdef12345678")

	if result.Value != "token: [MASKED:github-token]" {
		t.Fatalf("unexpected masked value: %s", result.Value)
	}
}

func TestMaskConnectionString(t *testing.T) {
	masker := mustMasker(t)
	result := masker.MaskString("postgres://user:pass@host:5432/db")

	if result.Value != "[MASKED:connection-string]" {
		t.Fatalf("unexpected masked value: %s", result.Value)
	}
}

func TestNoSecrets(t *testing.T) {
	masker := mustMasker(t)
	result := masker.MaskString("no secrets here")

	if result.Value != "no secrets here" {
		t.Fatalf("unexpected masked value: %s", result.Value)
	}
}

func TestMaskPrivateKeyHeader(t *testing.T) {
	masker := mustMasker(t)
	result := masker.MaskString("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")

	if result.Value != "[MASKED:private-key]\nMIIE..." {
		t.Fatalf("unexpected masked value: %s", result.Value)
	}
}

func TestMaskPrivateKeyBlock(t *testing.T) {
	masker := mustMasker(t)
	result := masker.MaskString("-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----")

	if result.Value != "[MASKED:private-key]" {
		t.Fatalf("unexpected masked value: %s", result.Value)
	}
}

func mustMasker(t *testing.T) *Masker {
	t.Helper()

	masker, err := NewMasker(Options{Enabled: true})
	if err != nil {
		t.Fatalf("failed to build masker: %s", err)
	}
	return masker
}
