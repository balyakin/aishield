package shim

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/balyakin/aishield/internal/policy"
)

func TestEvaluateBlocksDangerousRm(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)
	t.Setenv(EnvPreset, "standard")
	t.Setenv(EnvConfig, "")
	t.Setenv(EnvLogFile, "")

	evaluation, err := Evaluate("rm", []string{"-rf", "/tmp/test"})

	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if evaluation.Result.Decision != policy.Block {
		t.Fatalf("expected block, got %s", evaluation.Result.Decision)
	}
}

func TestEvaluateAllowsGitStatus(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)
	t.Setenv(EnvPreset, "standard")
	t.Setenv(EnvConfig, "")
	t.Setenv(EnvLogFile, "")

	evaluation, err := Evaluate("git", []string{"status"})

	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if evaluation.Result.Decision != policy.Allow {
		t.Fatalf("expected allow, got %s", evaluation.Result.Decision)
	}
}

func TestWarnNonInteractiveBlocksByDefault(t *testing.T) {
	result := policy.EvalResult{Decision: policy.Warn}

	allowed, code := ResolveWrapperDecision(result, policy.Block, time.Second)

	if allowed {
		t.Fatal("expected warn to block in non-interactive mode")
	}
	if code == 0 {
		t.Fatal("expected non-zero exit code")
	}
}

func TestFindRealExecutableUsesOriginalPath(t *testing.T) {
	tempDir := t.TempDir()
	realPath := filepath.Join(tempDir, "git")
	if err := os.WriteFile(realPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("failed to write executable: %s", err)
	}

	foundPath, err := FindRealExecutable("git", tempDir)

	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if foundPath != realPath {
		t.Fatalf("expected %s, got %s", realPath, foundPath)
	}
}
