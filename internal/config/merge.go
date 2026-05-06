package config

import (
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
