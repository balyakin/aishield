package config

import (
	"fmt"

	projectenv "github.com/balyakin/aishield/internal/env"
	"github.com/balyakin/aishield/internal/pii"
	"github.com/balyakin/aishield/internal/policy"
	"github.com/balyakin/aishield/internal/secrets"
	"github.com/balyakin/aishield/presets"
	"gopkg.in/yaml.v3"
)

func DefaultConfig() Config {
	return Config{
		Preset:                   DefaultPreset,
		DefaultAction:            policy.Allow,
		WarnActionNonInteractive: policy.Block,
		WorkDir:                  ".",
		FileSystem: FileSystemConfig{
			ReadOnly: []string{
				"/etc/*",
				"~/.ssh/*",
				"~/.gnupg/*",
				"~/.config/*",
			},
			Blocked: []string{
				"/System/*",
				"/boot/*",
			},
			SecretFiles: []string{
				".env",
				".env.*",
				"*.pem",
				"*.key",
				"id_rsa",
				"id_ed25519",
				"~/.ssh/**",
				"~/.aws/credentials",
				"~/.config/gcloud/**",
				"~/.docker/config.json",
				".npmrc",
				".pypirc",
			},
		},
		Enforcement: EnforcementConfig{
			PTY:          true,
			PathShim:     true,
			ShellWrapper: true,
			ShimExecutables: []string{
				"rm", "curl", "wget", "bash", "sh", "zsh", "git", "kubectl", "terraform", "aws", "gcloud",
				"az", "gh", "openai", "anthropic", "docker", "ssh", "scp", "rsync", "nc", "ncat", "netcat",
				"npm", "pnpm", "yarn", "pip", "brew",
			},
		},
		Secrets: SecretsConfig{
			Enabled: true,
			HighEntropy: secrets.HighEntropyConfig{
				Enabled:    false,
				MinLength:  32,
				MinEntropy: 4.5,
			},
		},
		PII: PIIConfig{
			Enabled:                true,
			Countries:              []string{"generic", "NL", "DE", "FR", "ES", "IT", "PL"},
			EntityTypes:            []string{},
			ReplacementMode:        pii.ReplacementFake,
			ContextWindow:          50,
			StreamBufferBytes:      4096,
			EncodedMinLength:       32,
			MaxScanBytes:           1048576,
			MaxStructuredBytes:     262144,
			EncodedMaxDecodedBytes: 65536,
			MaxFindingsPerInput:    500,
		},
		Audit: AuditConfig{
			Integrity: AuditIntegrityConfig{
				HMACKeyEnv: "AISHIELD_AUDIT_HMAC_KEY",
			},
		},
		Dashboard: DashboardConfig{
			Listen:      "127.0.0.1:17891",
			PasswordEnv: "AISHIELD_DASHBOARD_PASSWORD",
		},
		Logging: LoggingConfig{
			File: "aishield.log",
		},
		Environment: defaultEnvironment(),
		IncidentMode: IncidentModeConfig{
			OncePerDay: true,
		},
	}
}

func PresetConfig(name string) (Config, error) {
	presetConfig, _, err := loadPresetConfig(name)
	return presetConfig, err
}

func loadPresetConfig(name string) (Config, map[string]bool, error) {
	presetName := NormalizePresetName(name)
	if presetName != "strict" && presetName != "standard" && presetName != "permissive" {
		return Config{}, nil, fmt.Errorf("unknown preset %q", name)
	}

	data, err := presets.Read(presetName)
	if err != nil {
		return Config{}, nil, err
	}

	var presetConfig Config
	if err := yaml.Unmarshal(data, &presetConfig); err != nil {
		return Config{}, nil, fmt.Errorf("failed to decode preset %q: %w", presetName, err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return Config{}, nil, err
	}
	return presetConfig, collectPresentFields(&root), nil
}

func DefaultYAML(preset string) string {
	return fmt.Sprintf(`# aishield configuration
preset: %s
default_action: allow
warn_action_non_interactive: block
disabled_rules: []
work_dir: "."

filesystem:
  read_only:
    - "/etc/*"
    - "~/.ssh/*"
    - "~/.gnupg/*"
    - "~/.config/*"
  blocked:
    - "/System/*"
    - "/boot/*"
  secret_files:
    - ".env"
    - ".env.*"
    - "*.pem"
    - "*.key"
    - "id_rsa"
    - "id_ed25519"
    - "~/.ssh/**"
    - "~/.aws/credentials"
    - "~/.config/gcloud/**"
    - "~/.docker/config.json"
    - ".npmrc"
    - ".pypirc"

enforcement:
  pty: true
  path_shim: true
  shell_wrapper: true
  shim_executables:
    - rm
    - curl
    - wget
    - bash
    - sh
    - zsh
    - git
    - kubectl
    - terraform
    - aws
    - gcloud
    - az
    - gh
    - openai
    - anthropic
    - docker
    - ssh
    - scp
    - rsync
    - nc
    - ncat
    - netcat
    - npm
    - pnpm
    - yarn
    - pip
    - brew

rules:
  - name: "block-production-db"
    description: "Block commands that mention production database deletion"
    decision: block
    severity: critical
    match:
      raw_regex:
        - "(?i)prod.*drop"
        - "(?i)prod.*delete"
        - "(?i)prod.*destroy"

secrets:
  enabled: true
  high_entropy:
    enabled: false
    min_length: 32
    min_entropy: 4.5
  custom_patterns: []
  mask_strings: []

pii:
  enabled: true
  countries:
    - generic
    - NL
    - DE
    - FR
    - ES
    - IT
    - PL
  entity_types: []
  replacement_mode: fake
  context_window: 50
  stream_buffer_bytes: 4096
  scan_encoded: false
  encoded_min_length: 32
  max_scan_bytes: 1048576
  max_structured_bytes: 262144
  encoded_max_decoded_bytes: 65536
  max_findings_per_input: 500
  custom_patterns: []

audit:
  retention_days: 0
  archive_before_delete: false
  integrity:
    enabled: false
    hmac_key_env: AISHIELD_AUDIT_HMAC_KEY

dashboard:
  listen: "127.0.0.1:17891"
  password: ""
  password_env: AISHIELD_DASHBOARD_PASSWORD

logging:
  file: "aishield.log"
  log_output: false
  log_stdin: false

notifications:
  enabled: false
  slack:
    webhook_url: ""
    on_blocked: true
    on_warned: false
    on_secret_masked: true
    on_pii_found: false
    min_pii_count: 1
  webhook:
    url: ""
    on_blocked: true
    on_warned: true
    on_pii_found: false
    min_pii_count: 1

environment:
  allow_list: []
  block_list:
    - "DATABASE_URL"
    - "AWS_SECRET_ACCESS_KEY"
    - "AWS_ACCESS_KEY_ID"
    - "GITHUB_TOKEN"
    - "NPM_TOKEN"
    - "DOCKER_PASSWORD"
    - "RAILWAY_TOKEN"
    - "VERCEL_TOKEN"
  redact_list: []

incident_mode:
  enabled: false
  once_per_day: true
`, preset)
}

func defaultEnvironment() projectenv.Config {
	return projectenv.Config{
		BlockList: []string{
			"DATABASE_URL",
			"AWS_SECRET_ACCESS_KEY",
			"AWS_ACCESS_KEY_ID",
			"GITHUB_TOKEN",
			"NPM_TOKEN",
			"DOCKER_PASSWORD",
			"RAILWAY_TOKEN",
			"VERCEL_TOKEN",
		},
	}
}
