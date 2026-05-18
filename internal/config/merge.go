package config

import (
	"github.com/balyakin/aishield/internal/pii"
	"github.com/balyakin/aishield/internal/policy"
	"github.com/balyakin/aishield/internal/secrets"
)

func Merge(base Config, override Config) Config {
	result := base
	if override.Preset != "" {
		result.Preset = override.Preset
	}
	if override.DefaultAction != "" {
		result.DefaultAction = override.DefaultAction
	}
	if override.WarnActionNonInteractive != "" {
		result.WarnActionNonInteractive = override.WarnActionNonInteractive
	}
	if override.WorkDir != "" {
		result.WorkDir = override.WorkDir
	}
	if override.Enforcement.PTY {
		result.Enforcement.PTY = true
	}
	if override.Enforcement.PathShim {
		result.Enforcement.PathShim = true
	}
	if override.Enforcement.ShellWrapper {
		result.Enforcement.ShellWrapper = true
	}
	if override.Secrets.Enabled {
		result.Secrets.Enabled = true
	}
	if override.PII.Enabled {
		result.PII.Enabled = true
	}
	if override.PII.ReplacementMode != "" {
		result.PII.ReplacementMode = override.PII.ReplacementMode
	}
	if override.PII.ContextWindow != 0 {
		result.PII.ContextWindow = override.PII.ContextWindow
	}
	if override.PII.StreamBufferBytes != 0 {
		result.PII.StreamBufferBytes = override.PII.StreamBufferBytes
	}
	if override.PII.ScanEncoded {
		result.PII.ScanEncoded = true
	}
	if override.PII.EncodedMinLength != 0 {
		result.PII.EncodedMinLength = override.PII.EncodedMinLength
	}
	if override.PII.MaxScanBytes != 0 {
		result.PII.MaxScanBytes = override.PII.MaxScanBytes
	}
	if override.PII.MaxStructuredBytes != 0 {
		result.PII.MaxStructuredBytes = override.PII.MaxStructuredBytes
	}
	if override.PII.EncodedMaxDecodedBytes != 0 {
		result.PII.EncodedMaxDecodedBytes = override.PII.EncodedMaxDecodedBytes
	}
	if override.PII.MaxFindingsPerInput != 0 {
		result.PII.MaxFindingsPerInput = override.PII.MaxFindingsPerInput
	}
	if override.Secrets.HighEntropy.Enabled {
		result.Secrets.HighEntropy.Enabled = true
	}
	if override.Secrets.HighEntropy.MinLength != 0 {
		result.Secrets.HighEntropy.MinLength = override.Secrets.HighEntropy.MinLength
	}
	if override.Secrets.HighEntropy.MinEntropy != 0 {
		result.Secrets.HighEntropy.MinEntropy = override.Secrets.HighEntropy.MinEntropy
	}
	result.DisabledRules = append(result.DisabledRules, override.DisabledRules...)
	result.FileSystem.ReadOnly = uniqueStrings(append(result.FileSystem.ReadOnly, override.FileSystem.ReadOnly...))
	result.FileSystem.Blocked = uniqueStrings(append(result.FileSystem.Blocked, override.FileSystem.Blocked...))
	result.FileSystem.SecretFiles = uniqueStrings(append(result.FileSystem.SecretFiles, override.FileSystem.SecretFiles...))
	result.Enforcement.ShimExecutables = uniqueStrings(
		append(result.Enforcement.ShimExecutables, override.Enforcement.ShimExecutables...),
	)
	result.Rules = mergeRules(result.Rules, override.Rules)
	result.Secrets.CustomPatterns = mergeSecretPatterns(result.Secrets.CustomPatterns, override.Secrets.CustomPatterns)
	result.Secrets.MaskStrings = uniqueStrings(append(result.Secrets.MaskStrings, override.Secrets.MaskStrings...))
	result.PII.Countries = uniqueStrings(append(result.PII.Countries, override.PII.Countries...))
	result.PII.EntityTypes = uniqueStrings(append(result.PII.EntityTypes, override.PII.EntityTypes...))
	result.PII.CustomPatterns = mergePIIPatterns(result.PII.CustomPatterns, override.PII.CustomPatterns)
	if override.Audit.RetentionDays != 0 {
		result.Audit.RetentionDays = override.Audit.RetentionDays
	}
	if override.Audit.ArchiveBeforeDelete {
		result.Audit.ArchiveBeforeDelete = true
	}
	if override.Audit.Integrity.Enabled {
		result.Audit.Integrity.Enabled = true
	}
	if override.Audit.Integrity.HMACKeyEnv != "" {
		result.Audit.Integrity.HMACKeyEnv = override.Audit.Integrity.HMACKeyEnv
	}
	if override.Dashboard.Listen != "" {
		result.Dashboard.Listen = override.Dashboard.Listen
	}
	if override.Dashboard.Password != "" {
		result.Dashboard.Password = override.Dashboard.Password
	}
	if override.Dashboard.PasswordEnv != "" {
		result.Dashboard.PasswordEnv = override.Dashboard.PasswordEnv
	}
	result.Environment.AllowList = uniqueStrings(append(result.Environment.AllowList, override.Environment.AllowList...))
	result.Environment.BlockList = uniqueStrings(append(result.Environment.BlockList, override.Environment.BlockList...))
	result.Environment.RedactList = uniqueStrings(append(result.Environment.RedactList, override.Environment.RedactList...))
	result.Notifications = mergeNotifications(result.Notifications, override.Notifications)
	return result
}

func uniqueStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func MergePatch(base Config, override Config, present map[string]bool) Config {
	result := Merge(base, override)
	if present["enforcement.pty"] {
		result.Enforcement.PTY = override.Enforcement.PTY
	}
	if present["enforcement.path_shim"] {
		result.Enforcement.PathShim = override.Enforcement.PathShim
	}
	if present["enforcement.shell_wrapper"] {
		result.Enforcement.ShellWrapper = override.Enforcement.ShellWrapper
	}
	if present["secrets.enabled"] {
		result.Secrets.Enabled = override.Secrets.Enabled
	}
	if present["secrets.high_entropy.enabled"] {
		result.Secrets.HighEntropy.Enabled = override.Secrets.HighEntropy.Enabled
	}
	if present["secrets.high_entropy.min_length"] {
		result.Secrets.HighEntropy.MinLength = override.Secrets.HighEntropy.MinLength
	}
	if present["secrets.high_entropy.min_entropy"] {
		result.Secrets.HighEntropy.MinEntropy = override.Secrets.HighEntropy.MinEntropy
	}
	if present["pii.enabled"] {
		result.PII.Enabled = override.PII.Enabled
	}
	if present["pii.countries"] {
		result.PII.Countries = override.PII.Countries
	}
	if present["pii.entity_types"] {
		result.PII.EntityTypes = override.PII.EntityTypes
	}
	if present["pii.replacement_mode"] {
		result.PII.ReplacementMode = override.PII.ReplacementMode
	}
	if present["pii.context_window"] {
		result.PII.ContextWindow = override.PII.ContextWindow
	}
	if present["pii.stream_buffer_bytes"] {
		result.PII.StreamBufferBytes = override.PII.StreamBufferBytes
	}
	if present["pii.scan_encoded"] {
		result.PII.ScanEncoded = override.PII.ScanEncoded
	}
	if present["pii.encoded_min_length"] {
		result.PII.EncodedMinLength = override.PII.EncodedMinLength
	}
	if present["pii.max_scan_bytes"] {
		result.PII.MaxScanBytes = override.PII.MaxScanBytes
	}
	if present["pii.max_structured_bytes"] {
		result.PII.MaxStructuredBytes = override.PII.MaxStructuredBytes
	}
	if present["pii.encoded_max_decoded_bytes"] {
		result.PII.EncodedMaxDecodedBytes = override.PII.EncodedMaxDecodedBytes
	}
	if present["pii.max_findings_per_input"] {
		result.PII.MaxFindingsPerInput = override.PII.MaxFindingsPerInput
	}
	if present["pii.custom_patterns"] {
		result.PII.CustomPatterns = override.PII.CustomPatterns
	}
	if present["audit.retention_days"] {
		result.Audit.RetentionDays = override.Audit.RetentionDays
	}
	if present["audit.archive_before_delete"] {
		result.Audit.ArchiveBeforeDelete = override.Audit.ArchiveBeforeDelete
	}
	if present["audit.integrity.enabled"] {
		result.Audit.Integrity.Enabled = override.Audit.Integrity.Enabled
	}
	if present["audit.integrity.hmac_key_env"] {
		result.Audit.Integrity.HMACKeyEnv = override.Audit.Integrity.HMACKeyEnv
	}
	if present["dashboard.listen"] {
		result.Dashboard.Listen = override.Dashboard.Listen
	}
	if present["dashboard.password"] {
		result.Dashboard.Password = override.Dashboard.Password
	}
	if present["dashboard.password_env"] {
		result.Dashboard.PasswordEnv = override.Dashboard.PasswordEnv
	}
	if present["logging.file"] {
		result.Logging.File = override.Logging.File
	}
	if present["logging.log_output"] {
		result.Logging.LogOutput = override.Logging.LogOutput
	}
	if present["logging.log_stdin"] {
		result.Logging.LogStdin = override.Logging.LogStdin
	}
	if present["notifications.enabled"] {
		result.Notifications.Enabled = override.Notifications.Enabled
	}
	if present["notifications.slack.url"] {
		result.Notifications.Slack.URL = override.Notifications.Slack.URL
	}
	if present["notifications.slack.webhook_url"] {
		result.Notifications.Slack.WebhookURL = override.Notifications.Slack.WebhookURL
	}
	if present["notifications.slack.headers"] {
		result.Notifications.Slack.Headers = mergeStringMap(result.Notifications.Slack.Headers, override.Notifications.Slack.Headers)
	}
	if present["notifications.slack.on_blocked"] {
		result.Notifications.Slack.OnBlocked = override.Notifications.Slack.OnBlocked
	}
	if present["notifications.slack.on_warned"] {
		result.Notifications.Slack.OnWarned = override.Notifications.Slack.OnWarned
	}
	if present["notifications.slack.on_secret_masked"] {
		result.Notifications.Slack.OnSecretMasked = override.Notifications.Slack.OnSecretMasked
	}
	if present["notifications.slack.on_pii_found"] {
		result.Notifications.Slack.OnPIIFound = override.Notifications.Slack.OnPIIFound
	}
	if present["notifications.slack.min_pii_count"] {
		result.Notifications.Slack.MinPIICount = override.Notifications.Slack.MinPIICount
	}
	if present["notifications.slack.min_severity"] {
		result.Notifications.Slack.MinSeverity = override.Notifications.Slack.MinSeverity
	}
	if present["notifications.webhook.url"] {
		result.Notifications.Webhook.URL = override.Notifications.Webhook.URL
	}
	if present["notifications.webhook.webhook_url"] {
		result.Notifications.Webhook.WebhookURL = override.Notifications.Webhook.WebhookURL
	}
	if present["notifications.webhook.headers"] {
		result.Notifications.Webhook.Headers = mergeStringMap(
			result.Notifications.Webhook.Headers,
			override.Notifications.Webhook.Headers,
		)
	}
	if present["notifications.webhook.on_blocked"] {
		result.Notifications.Webhook.OnBlocked = override.Notifications.Webhook.OnBlocked
	}
	if present["notifications.webhook.on_warned"] {
		result.Notifications.Webhook.OnWarned = override.Notifications.Webhook.OnWarned
	}
	if present["notifications.webhook.on_secret_masked"] {
		result.Notifications.Webhook.OnSecretMasked = override.Notifications.Webhook.OnSecretMasked
	}
	if present["notifications.webhook.on_pii_found"] {
		result.Notifications.Webhook.OnPIIFound = override.Notifications.Webhook.OnPIIFound
	}
	if present["notifications.webhook.min_pii_count"] {
		result.Notifications.Webhook.MinPIICount = override.Notifications.Webhook.MinPIICount
	}
	if present["notifications.webhook.min_severity"] {
		result.Notifications.Webhook.MinSeverity = override.Notifications.Webhook.MinSeverity
	}
	if present["incident_mode.enabled"] {
		result.IncidentMode.Enabled = override.IncidentMode.Enabled
	}
	if present["incident_mode.once_per_day"] {
		result.IncidentMode.OncePerDay = override.IncidentMode.OncePerDay
	}
	return result
}

func mergeNotifications(base NotificationsConfig, override NotificationsConfig) NotificationsConfig {
	result := base
	if override.Enabled {
		result.Enabled = true
	}
	result.Slack = mergeWebhook(result.Slack, override.Slack)
	result.Webhook = mergeWebhook(result.Webhook, override.Webhook)
	return result
}

func mergeWebhook(base WebhookConfig, override WebhookConfig) WebhookConfig {
	result := base
	if override.URL != "" {
		result.URL = override.URL
	}
	if override.WebhookURL != "" {
		result.WebhookURL = override.WebhookURL
	}
	result.Headers = mergeStringMap(result.Headers, override.Headers)
	if override.OnBlocked {
		result.OnBlocked = true
	}
	if override.OnWarned {
		result.OnWarned = true
	}
	if override.OnSecretMasked {
		result.OnSecretMasked = true
	}
	if override.OnPIIFound {
		result.OnPIIFound = true
	}
	if override.MinPIICount != 0 {
		result.MinPIICount = override.MinPIICount
	}
	if override.MinSeverity != "" {
		result.MinSeverity = override.MinSeverity
	}
	return result
}

func mergeStringMap(base map[string]string, override map[string]string) map[string]string {
	if len(base) == 0 && len(override) == 0 {
		return nil
	}

	result := make(map[string]string)
	for key, value := range base {
		result[key] = value
	}
	for key, value := range override {
		result[key] = value
	}
	return result
}

func mergeRules(base []policy.Rule, override []policy.Rule) []policy.Rule {
	result := append([]policy.Rule{}, base...)
	indexByName := make(map[string]int)
	for index, rule := range result {
		if rule.Name != "" {
			indexByName[rule.Name] = index
		}
	}

	for _, rule := range override {
		if rule.Name == "" {
			result = append(result, rule)
			continue
		}
		index, ok := indexByName[rule.Name]
		if ok {
			result[index] = rule
			continue
		}
		indexByName[rule.Name] = len(result)
		result = append(result, rule)
	}
	return result
}

func mergeSecretPatterns(base []secrets.PatternConfig, override []secrets.PatternConfig) []secrets.PatternConfig {
	result := append([]secrets.PatternConfig{}, base...)
	indexByName := make(map[string]int)
	for index, pattern := range result {
		if pattern.Name != "" {
			indexByName[pattern.Name] = index
		}
	}

	for _, pattern := range override {
		if pattern.Name == "" {
			result = append(result, pattern)
			continue
		}
		index, ok := indexByName[pattern.Name]
		if ok {
			result[index] = pattern
			continue
		}
		indexByName[pattern.Name] = len(result)
		result = append(result, pattern)
	}
	return result
}

func mergePIIPatterns(base []pii.PatternConfig, override []pii.PatternConfig) []pii.PatternConfig {
	result := append([]pii.PatternConfig{}, base...)
	indexByName := make(map[string]int)
	for index, pattern := range result {
		if pattern.Name != "" {
			indexByName[pattern.Name] = index
		}
	}

	for _, pattern := range override {
		if pattern.Name == "" {
			result = append(result, pattern)
			continue
		}
		index, ok := indexByName[pattern.Name]
		if ok {
			result[index] = pattern
			continue
		}
		indexByName[pattern.Name] = len(result)
		result = append(result, pattern)
	}
	return result
}
