package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInvalidRegex(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)
	configPath := filepath.Join(tempDir, ".aishield.yaml")
	data := []byte("rules:\n  - name: invalid\n    decision: block\n    match:\n      raw_regex:\n        - \"(\"\n")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("failed to write config: %s", err)
	}

	_, err := Load(LoadOptions{ConfigPath: configPath, ConfigChanged: true})

	if err == nil {
		t.Fatal("expected invalid regex error")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestUnknownYAMLField(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)
	configPath := filepath.Join(tempDir, ".aishield.yaml")
	data := []byte("unknown_field: true\n")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("failed to write config: %s", err)
	}

	_, err := Load(LoadOptions{ConfigPath: configPath, ConfigChanged: true})

	if err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestValidStandardConfig(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	loadedConfig, err := Load(LoadOptions{})

	if err != nil {
		t.Fatalf("expected valid config: %s", err)
	}
	if loadedConfig.Preset != "standard" {
		t.Fatalf("expected standard preset, got %s", loadedConfig.Preset)
	}
	if len(loadedConfig.Rules) == 0 {
		t.Fatal("expected preset rules")
	}
}

func TestStrictPresetEnablesHighEntropy(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	loadedConfig, err := Load(LoadOptions{Preset: "strict", PresetChanged: true})

	if err != nil {
		t.Fatalf("expected valid config: %s", err)
	}
	if !loadedConfig.Secrets.HighEntropy.Enabled {
		t.Fatal("expected strict preset to enable high entropy masking")
	}
}

func TestNotificationsLoadedFromConfig(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)
	configPath := filepath.Join(tempDir, ".aishield.yaml")
	data := []byte(`
notifications:
  enabled: true
  slack:
    webhook_url: "https://hooks.example/slack"
    on_blocked: true
    on_warned: true
    on_secret_masked: true
    min_severity: warn
  webhook:
    url: "https://hooks.example/generic"
    headers:
      Authorization: "Bearer token"
    on_blocked: true
    on_warned: true
`)
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("failed to write config: %s", err)
	}

	loadedConfig, err := Load(LoadOptions{ConfigPath: configPath, ConfigChanged: true})

	if err != nil {
		t.Fatalf("expected valid config: %s", err)
	}
	if !loadedConfig.Notifications.Enabled {
		t.Fatal("expected notifications to be enabled")
	}
	if loadedConfig.Notifications.Slack.WebhookURL != "https://hooks.example/slack" {
		t.Fatalf("unexpected slack webhook: %s", loadedConfig.Notifications.Slack.WebhookURL)
	}
	if !loadedConfig.Notifications.Slack.OnWarned {
		t.Fatal("expected slack warned events enabled")
	}
	if loadedConfig.Notifications.Webhook.Headers["Authorization"] != "Bearer token" {
		t.Fatalf("unexpected webhook headers: %#v", loadedConfig.Notifications.Webhook.Headers)
	}
}

func TestEmbeddedPresetMatchesPolicyRules(t *testing.T) {
	strictConfig, err := PresetConfig("strict")
	if err != nil {
		t.Fatalf("failed to load strict preset: %s", err)
	}
	standardConfig, err := PresetConfig("standard")
	if err != nil {
		t.Fatalf("failed to load standard preset: %s", err)
	}

	if len(strictConfig.Rules) != 11 {
		t.Fatalf("unexpected strict rule count: %d", len(strictConfig.Rules))
	}
	if len(standardConfig.Rules) != 11 {
		t.Fatalf("unexpected standard rule count: %d", len(standardConfig.Rules))
	}
}
