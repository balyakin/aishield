package cli

import (
	"testing"

	"github.com/balyakin/aishield/internal/config"
)

func TestSanitizedConfigForPrintRedactsSensitiveValues(t *testing.T) {
	loadedConfig := config.DefaultConfig()
	loadedConfig.Dashboard.Password = "secret"
	loadedConfig.Notifications.Slack.WebhookURL = "https://hooks.example/slack"
	loadedConfig.Notifications.Webhook.URL = "https://hooks.example/generic"
	loadedConfig.Notifications.Webhook.Headers = map[string]string{"Authorization": "Bearer token", "X-Team": "security"}

	sanitized := sanitizedConfigForPrint(loadedConfig)

	if sanitized.Dashboard.Password != "[REDACTED]" {
		t.Fatalf("dashboard password was not redacted: %#v", sanitized.Dashboard)
	}
	if sanitized.Notifications.Slack.WebhookURL != "[REDACTED]" || sanitized.Notifications.Webhook.URL != "[REDACTED]" {
		t.Fatalf("webhook URLs were not redacted: %#v", sanitized.Notifications)
	}
	if sanitized.Notifications.Webhook.Headers["Authorization"] != "[REDACTED]" {
		t.Fatalf("authorization header was not redacted: %#v", sanitized.Notifications.Webhook.Headers)
	}
	if sanitized.Notifications.Webhook.Headers["X-Team"] != "security" {
		t.Fatalf("non-secret header should be preserved: %#v", sanitized.Notifications.Webhook.Headers)
	}
}
