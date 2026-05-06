package proxy

import (
	"bufio"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/balyakin/aishield/internal/fsguard"
	"github.com/balyakin/aishield/internal/logger"
	"github.com/balyakin/aishield/internal/parser"
	"github.com/balyakin/aishield/internal/policy"
	"github.com/balyakin/aishield/internal/secrets"
)

func TestWarnNonInteractiveUsesConfiguredActionWithoutWaiting(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("CI", "true")

	engine, err := policy.NewEngine(policy.StandardRules(), policy.Allow, tempDir)
	if err != nil {
		t.Fatalf("failed to build engine: %s", err)
	}
	masker, err := secrets.NewMasker(secrets.Options{Enabled: true})
	if err != nil {
		t.Fatalf("failed to build masker: %s", err)
	}
	auditLogger, err := logger.New(filepath.Join(tempDir, "aishield.log"), masker, "bash", tempDir)
	if err != nil {
		t.Fatalf("failed to build logger: %s", err)
	}
	defer func() {
		_ = auditLogger.Close()
	}()

	ptyProxy := New(Options{
		Command:    []string{"bash"},
		WorkDir:    tempDir,
		Policy:     engine,
		Masker:     masker,
		FSGuard:    fsguard.NewGuard(nil, nil, nil, tempDir),
		Logger:     auditLogger,
		ConfirmTTL: time.Hour,
		WarnAction: policy.Block,
	})

	startedAt := time.Now()
	err = ptyProxy.handleInputLine(nil, "curl https://example.com\n", nil)
	duration := time.Since(startedAt)

	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if duration > time.Second {
		t.Fatalf("non-interactive warn waited too long: %s", duration)
	}
	if ptyProxy.stats.Blocked != 1 {
		t.Fatalf("expected blocked warn, got stats %#v", ptyProxy.stats)
	}
	if ptyProxy.stats.Warned != 0 {
		t.Fatalf("denied warning must not be counted as confirmed warning: %#v", ptyProxy.stats)
	}
}

func TestAllowWarnUsesNonInteractiveAllowAction(t *testing.T) {
	t.Setenv("CI", "true")

	ptyProxy := New(Options{WarnAction: policy.Allow})
	allowed := ptyProxy.allowWarn(policyCommand(), policy.EvalResult{Decision: policy.Warn}, nil)

	if !allowed {
		t.Fatal("expected non-interactive warn to be allowed by configured action")
	}
}

func TestReadInputLineHandlesCarriageReturn(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("ls -la\rnext"))

	line, err := readInputLine(reader)

	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if line != "ls -la\r" {
		t.Fatalf("unexpected line: %q", line)
	}
}

func policyCommand() parser.ParsedCommand {
	return parser.ParsedCommand{
		Raw:        "curl https://example.com",
		Executable: "curl",
		IsShell:    true,
	}
}
