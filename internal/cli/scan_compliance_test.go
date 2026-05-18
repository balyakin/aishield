package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/balyakin/aishield/internal/config"
	"github.com/balyakin/aishield/internal/policy"
)

func TestScanAuditUsesDataProtectionPipeline(t *testing.T) {
	tempDir := t.TempDir()
	loadedConfig := config.DefaultConfig()
	loadedConfig.WorkDir = tempDir
	loadedConfig.Logging.File = filepath.Join(tempDir, "aishield.log")

	protector, err := config.NewDataProtector(loadedConfig)
	if err != nil {
		t.Fatalf("failed to build protector: %s", err)
	}
	protectionResult := protector.ProtectString("AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstABCDEFGHIJKLMNOP")
	if err := logScanEvent(loadedConfig, protectionResult); err != nil {
		t.Fatalf("failed to log scan event: %s", err)
	}

	data, err := os.ReadFile(loadedConfig.Logging.File)
	if err != nil {
		t.Fatalf("failed to read log: %s", err)
	}
	if strings.Contains(string(data), "abcdefghijklmnopqrstABCDEFGHIJKLMNOP") {
		t.Fatalf("scan audit leaked original secret: %s", string(data))
	}
	if !strings.Contains(string(data), "[MASKED:aws-secret]") || !strings.Contains(string(data), "secret_counts") {
		t.Fatalf("scan audit did not contain masked secret metadata: %s", string(data))
	}
}

func TestEvaluateCommandRecognizesRequiredNetworkCLIs(t *testing.T) {
	loadedConfig := config.DefaultConfig()
	loadedConfig.WorkDir = t.TempDir()
	loadedConfig.Rules = policy.StandardRules()

	decision, err := evaluateCommand(loadedConfig, "gh api -f email=john@example.com")
	if err != nil {
		t.Fatalf("unexpected evaluation error: %s", err)
	}
	if decision.Result.Decision != policy.Warn || decision.Result.Rule != "warn-pii-network-egress" {
		t.Fatalf("expected PII network egress warning, got %#v", decision.Result)
	}
}

func TestEvaluateCommandDoesNotTreatLowConfidenceRawEmailAsPIIEgress(t *testing.T) {
	loadedConfig := config.DefaultConfig()
	loadedConfig.WorkDir = t.TempDir()
	loadedConfig.Rules = policy.StandardRules()

	decision, err := evaluateCommand(loadedConfig, "openai api john@example.com")
	if err != nil {
		t.Fatalf("unexpected evaluation error: %s", err)
	}
	if decision.Result.Decision != policy.Allow {
		t.Fatalf("low-confidence raw email should not trigger PII egress rule: %#v", decision.Result)
	}
}
