package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/balyakin/aishield/internal/dataprotection"
	projectenv "github.com/balyakin/aishield/internal/env"
	"github.com/balyakin/aishield/internal/pii"
	"github.com/balyakin/aishield/internal/policy"
	"github.com/balyakin/aishield/internal/secrets"
	"gopkg.in/yaml.v3"
)

const DefaultPreset = "standard"

type Config struct {
	Preset                   string              `json:"preset" yaml:"preset"`
	DefaultAction            policy.Decision     `json:"default_action" yaml:"default_action"`
	WarnActionNonInteractive policy.Decision     `json:"warn_action_non_interactive" yaml:"warn_action_non_interactive"`
	DisabledRules            []string            `json:"disabled_rules" yaml:"disabled_rules"`
	WorkDir                  string              `json:"work_dir" yaml:"work_dir"`
	FileSystem               FileSystemConfig    `json:"filesystem" yaml:"filesystem"`
	Enforcement              EnforcementConfig   `json:"enforcement" yaml:"enforcement"`
	Rules                    []policy.Rule       `json:"rules" yaml:"rules"`
	Secrets                  SecretsConfig       `json:"secrets" yaml:"secrets"`
	PII                      PIIConfig           `json:"pii" yaml:"pii"`
	Audit                    AuditConfig         `json:"audit" yaml:"audit"`
	Dashboard                DashboardConfig     `json:"dashboard" yaml:"dashboard"`
	Logging                  LoggingConfig       `json:"logging" yaml:"logging"`
	Notifications            NotificationsConfig `json:"notifications" yaml:"notifications"`
	Environment              projectenv.Config   `json:"environment" yaml:"environment"`
	IncidentMode             IncidentModeConfig  `json:"incident_mode" yaml:"incident_mode"`
}

type FileSystemConfig struct {
	ReadOnly    []string `json:"read_only" yaml:"read_only"`
	Blocked     []string `json:"blocked" yaml:"blocked"`
	SecretFiles []string `json:"secret_files" yaml:"secret_files"`
}

type EnforcementConfig struct {
	PTY             bool     `json:"pty" yaml:"pty"`
	PathShim        bool     `json:"path_shim" yaml:"path_shim"`
	ShellWrapper    bool     `json:"shell_wrapper" yaml:"shell_wrapper"`
	ShimExecutables []string `json:"shim_executables" yaml:"shim_executables"`
}

type SecretsConfig struct {
	Enabled        bool                      `json:"enabled" yaml:"enabled"`
	HighEntropy    secrets.HighEntropyConfig `json:"high_entropy" yaml:"high_entropy"`
	CustomPatterns []secrets.PatternConfig   `json:"custom_patterns" yaml:"custom_patterns"`
	MaskStrings    []string                  `json:"mask_strings" yaml:"mask_strings"`
}

type LoggingConfig struct {
	File      string `json:"file" yaml:"file"`
	LogOutput bool   `json:"log_output" yaml:"log_output"`
	LogStdin  bool   `json:"log_stdin" yaml:"log_stdin"`
}

type PIIConfig struct {
	Enabled                bool                `json:"enabled" yaml:"enabled"`
	Countries              []string            `json:"countries" yaml:"countries"`
	EntityTypes            []string            `json:"entity_types" yaml:"entity_types"`
	ReplacementMode        pii.ReplacementMode `json:"replacement_mode" yaml:"replacement_mode"`
	ContextWindow          int                 `json:"context_window" yaml:"context_window"`
	StreamBufferBytes      int                 `json:"stream_buffer_bytes" yaml:"stream_buffer_bytes"`
	ScanEncoded            bool                `json:"scan_encoded" yaml:"scan_encoded"`
	EncodedMinLength       int                 `json:"encoded_min_length" yaml:"encoded_min_length"`
	MaxScanBytes           int                 `json:"max_scan_bytes" yaml:"max_scan_bytes"`
	MaxStructuredBytes     int                 `json:"max_structured_bytes" yaml:"max_structured_bytes"`
	EncodedMaxDecodedBytes int                 `json:"encoded_max_decoded_bytes" yaml:"encoded_max_decoded_bytes"`
	MaxFindingsPerInput    int                 `json:"max_findings_per_input" yaml:"max_findings_per_input"`
	CustomPatterns         []pii.PatternConfig `json:"custom_patterns" yaml:"custom_patterns"`
}

type AuditConfig struct {
	RetentionDays       int                  `json:"retention_days" yaml:"retention_days"`
	ArchiveBeforeDelete bool                 `json:"archive_before_delete" yaml:"archive_before_delete"`
	Integrity           AuditIntegrityConfig `json:"integrity" yaml:"integrity"`
}

type AuditIntegrityConfig struct {
	Enabled    bool   `json:"enabled" yaml:"enabled"`
	HMACKeyEnv string `json:"hmac_key_env" yaml:"hmac_key_env"`
}

type DashboardConfig struct {
	Listen      string `json:"listen" yaml:"listen"`
	Password    string `json:"password" yaml:"password"`
	PasswordEnv string `json:"password_env" yaml:"password_env"`
}

type NotificationsConfig struct {
	Enabled bool          `json:"enabled" yaml:"enabled"`
	Slack   WebhookConfig `json:"slack" yaml:"slack"`
	Webhook WebhookConfig `json:"webhook" yaml:"webhook"`
}

type WebhookConfig struct {
	URL            string            `json:"url" yaml:"url"`
	WebhookURL     string            `json:"webhook_url" yaml:"webhook_url"`
	Headers        map[string]string `json:"headers" yaml:"headers"`
	OnBlocked      bool              `json:"on_blocked" yaml:"on_blocked"`
	OnWarned       bool              `json:"on_warned" yaml:"on_warned"`
	OnSecretMasked bool              `json:"on_secret_masked" yaml:"on_secret_masked"`
	OnPIIFound     bool              `json:"on_pii_found" yaml:"on_pii_found"`
	MinPIICount    int               `json:"min_pii_count" yaml:"min_pii_count"`
	MinSeverity    string            `json:"min_severity" yaml:"min_severity"`
}

type IncidentModeConfig struct {
	Enabled    bool `json:"enabled" yaml:"enabled"`
	OncePerDay bool `json:"once_per_day" yaml:"once_per_day"`
}

type LoadOptions struct {
	Preset         string
	PresetChanged  bool
	ConfigPath     string
	ConfigChanged  bool
	LogFile        string
	LogFileChanged bool
	NoMask         bool
}

type fileConfig struct {
	Path    string
	Config  Config
	Present map[string]bool
}

func Load(options LoadOptions) (Config, error) {
	sources, err := loadSources(options)
	if err != nil {
		return Config{}, err
	}

	presetName := DefaultPreset
	for _, source := range sources {
		if source.Present["preset"] && source.Config.Preset != "" {
			presetName = source.Config.Preset
		}
	}
	if options.PresetChanged {
		presetName = options.Preset
	}
	if presetName == "" {
		presetName = DefaultPreset
	}

	config := DefaultConfig()
	presetConfig, presetPresent, err := loadPresetConfig(presetName)
	if err != nil {
		return Config{}, err
	}
	config = MergePatch(config, presetConfig, presetPresent)

	for _, source := range sources {
		config = MergePatch(config, source.Config, source.Present)
	}

	config.Preset = presetName
	if options.LogFileChanged {
		config.Logging.File = options.LogFile
	}
	if options.NoMask {
		config.Secrets.Enabled = false
		config.PII.Enabled = false
	}

	absoluteWorkDir, err := filepath.Abs(config.WorkDir)
	if err != nil {
		return Config{}, err
	}
	config.WorkDir = absoluteWorkDir

	config.Rules = applyDisabledRules(config.Rules, config.DisabledRules)
	if err := Validate(config); err != nil {
		return Config{}, err
	}
	return config, nil
}

func Validate(config Config) error {
	if !isDecision(config.DefaultAction) {
		return fmt.Errorf("default_action must be allow, warn, or block")
	}
	if !isDecision(config.WarnActionNonInteractive) {
		return fmt.Errorf("warn_action_non_interactive must be allow, warn, or block")
	}
	if _, err := policy.NewEngine(config.Rules, config.DefaultAction, config.WorkDir); err != nil {
		return err
	}
	for _, pattern := range config.Secrets.CustomPatterns {
		if pattern.Name == "" {
			return errors.New("secret custom pattern name is required")
		}
		if _, err := secrets.NewMasker(secrets.Options{
			Enabled:        true,
			CustomPatterns: []secrets.PatternConfig{pattern},
		}); err != nil {
			return fmt.Errorf("secret pattern %q is invalid: %w", pattern.Name, err)
		}
	}
	if _, err := NewPIIScanner(config); err != nil {
		return err
	}
	if config.Audit.RetentionDays < 0 {
		return errors.New("audit.retention_days must be non-negative")
	}
	return nil
}

func NewMasker(config Config) (*secrets.Masker, error) {
	return secrets.NewMasker(secrets.Options{
		Enabled:        config.Secrets.Enabled,
		HighEntropy:    config.Secrets.HighEntropy,
		CustomPatterns: config.Secrets.CustomPatterns,
		MaskStrings:    config.Secrets.MaskStrings,
	})
}

func NewPIIScanner(config Config) (*pii.Scanner, error) {
	return pii.NewScanner(pii.Options{
		Enabled:                config.PII.Enabled,
		Countries:              config.PII.Countries,
		EntityTypes:            config.PII.EntityTypes,
		ReplacementMode:        config.PII.ReplacementMode,
		ContextWindow:          config.PII.ContextWindow,
		StreamBufferBytes:      config.PII.StreamBufferBytes,
		ScanEncoded:            config.PII.ScanEncoded,
		EncodedMinLength:       config.PII.EncodedMinLength,
		MaxScanBytes:           config.PII.MaxScanBytes,
		MaxStructuredBytes:     config.PII.MaxStructuredBytes,
		EncodedMaxDecodedBytes: config.PII.EncodedMaxDecodedBytes,
		MaxFindingsPerInput:    config.PII.MaxFindingsPerInput,
		CustomPatterns:         config.PII.CustomPatterns,
		SecretsEnabled:         config.Secrets.Enabled,
	})
}

func NewDataProtector(config Config) (*dataprotection.Processor, error) {
	masker, err := NewMasker(config)
	if err != nil {
		return nil, err
	}
	scanner, err := NewPIIScanner(config)
	if err != nil {
		return nil, err
	}
	return dataprotection.New(masker, scanner), nil
}

func Marshal(config Config) ([]byte, error) {
	return yaml.Marshal(config)
}

func loadSources(options LoadOptions) ([]fileConfig, error) {
	sources := make([]fileConfig, 0)
	globalPath := globalConfigPath()
	if fileExists(globalPath) {
		source, err := loadConfigFile(globalPath)
		if err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}

	projectPath := ".aishield.yaml"
	if options.ConfigChanged {
		projectPath = options.ConfigPath
	}
	if projectPath != "" && fileExists(projectPath) {
		source, err := loadConfigFile(projectPath)
		if err != nil {
			return nil, err
		}
		sources = append(sources, source)
		return sources, nil
	}
	if options.ConfigChanged {
		return nil, fmt.Errorf("config file %q does not exist", options.ConfigPath)
	}
	return sources, nil
}

func loadConfigFile(path string) (fileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return fileConfig{}, err
	}

	var config Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return fileConfig{}, fmt.Errorf("failed to decode %s: %w", path, err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fileConfig{}, err
	}

	return fileConfig{
		Path:    path,
		Config:  config,
		Present: collectPresentFields(&root),
	}, nil
}

func globalConfigPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(homeDir, ".config", "aishield", "config.yaml")
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func collectPresentFields(root *yaml.Node) map[string]bool {
	present := make(map[string]bool)
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return present
	}
	collectMappingFields(root.Content[0], "", present)
	return present
}

func collectMappingFields(node *yaml.Node, prefix string, present map[string]bool) {
	if node.Kind != yaml.MappingNode {
		return
	}
	for index := 0; index < len(node.Content); index += 2 {
		keyNode := node.Content[index]
		valueNode := node.Content[index+1]
		fieldPath := keyNode.Value
		if prefix != "" {
			fieldPath = prefix + "." + keyNode.Value
		}
		present[fieldPath] = true
		collectMappingFields(valueNode, fieldPath, present)
	}
}

func isDecision(value policy.Decision) bool {
	return value == policy.Allow || value == policy.Warn || value == policy.Block
}

func applyDisabledRules(rules []policy.Rule, disabledRules []string) []policy.Rule {
	if len(disabledRules) == 0 {
		return rules
	}
	disabled := make(map[string]bool)
	for _, ruleName := range disabledRules {
		disabled[ruleName] = true
	}

	result := make([]policy.Rule, 0, len(rules))
	for _, rule := range rules {
		if disabled[rule.Name] {
			continue
		}
		result = append(result, rule)
	}
	return result
}

func NormalizePresetName(name string) string {
	return strings.TrimSpace(strings.ToLower(name))
}
