package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/balyakin/aishield/internal/config"
	"github.com/balyakin/aishield/internal/policy"
)

const (
	EventBlocked      = "blocked"
	EventWarned       = "warned"
	EventSecretMasked = "secret_masked"
)

type Notifier struct {
	config config.NotificationsConfig
	client *http.Client
}

type Event struct {
	Timestamp        string `json:"timestamp"`
	SessionID        string `json:"session_id"`
	EventType        string `json:"event_type"`
	Command          string `json:"command,omitempty"`
	Rule             string `json:"rule,omitempty"`
	Reason           string `json:"reason,omitempty"`
	Agent            string `json:"agent,omitempty"`
	Severity         string `json:"severity,omitempty"`
	User             string `json:"user,omitempty"`
	Host             string `json:"host,omitempty"`
	WorkingDirectory string `json:"working_directory,omitempty"`
}

func New(notificationsConfig config.NotificationsConfig) *Notifier {
	return NewWithClient(notificationsConfig, &http.Client{Timeout: 5 * time.Second})
}

func NewWithClient(notificationsConfig config.NotificationsConfig, client *http.Client) *Notifier {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Notifier{
		config: notificationsConfig,
		client: client,
	}
}

func (notifier *Notifier) Notify(ctx context.Context, event Event) error {
	if notifier == nil || !notifier.config.Enabled {
		return nil
	}

	event = enrichEvent(event)
	if err := notifier.sendSlack(ctx, event); err != nil {
		return err
	}
	return notifier.sendWebhook(ctx, event)
}

func (notifier *Notifier) sendSlack(ctx context.Context, event Event) error {
	webhookConfig := notifier.config.Slack
	webhookURL := webhookConfig.WebhookURL
	if webhookURL == "" {
		webhookURL = webhookConfig.URL
	}
	if webhookURL == "" || !shouldSend(webhookConfig, event) {
		return nil
	}

	payload := map[string]string{
		"text": formatSlackText(event),
	}
	return notifier.postJSON(ctx, webhookURL, nil, payload)
}

func (notifier *Notifier) sendWebhook(ctx context.Context, event Event) error {
	webhookConfig := notifier.config.Webhook
	if webhookConfig.URL == "" || !shouldSend(webhookConfig, event) {
		return nil
	}
	return notifier.postJSON(ctx, webhookConfig.URL, webhookConfig.Headers, event)
}

func (notifier *Notifier) postJSON(
	ctx context.Context,
	url string,
	headers map[string]string,
	payload interface{},
) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		request.Header.Set(key, value)
	}

	response, err := notifier.client.Do(request)
	if err != nil {
		return err
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("notification webhook returned status %d", response.StatusCode)
	}
	return nil
}

func shouldSend(webhookConfig config.WebhookConfig, event Event) bool {
	if !meetsSeverity(webhookConfig.MinSeverity, event.Severity) {
		return false
	}

	switch event.EventType {
	case EventBlocked:
		return webhookConfig.OnBlocked
	case EventWarned:
		return webhookConfig.OnWarned
	case EventSecretMasked:
		return webhookConfig.OnSecretMasked
	default:
		return false
	}
}

func meetsSeverity(minSeverity string, eventSeverity string) bool {
	return severityRank(eventSeverity) >= severityRank(minSeverity)
}

func severityRank(severity string) int {
	switch severity {
	case policy.SeverityCritical:
		return 3
	case policy.SeverityWarn:
		return 2
	default:
		return 1
	}
}

func enrichEvent(event Event) Event {
	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if event.User == "" {
		event.User = os.Getenv("USER")
	}
	if event.Host == "" {
		host, err := os.Hostname()
		if err == nil {
			event.Host = host
		}
	}
	return event
}

func formatSlackText(event Event) string {
	if event.Command == "" {
		return fmt.Sprintf("aishield %s: %s", event.EventType, event.Reason)
	}
	return fmt.Sprintf(
		"aishield %s: %s\nrule=%s severity=%s reason=%s",
		event.EventType,
		event.Command,
		event.Rule,
		event.Severity,
		event.Reason,
	)
}
