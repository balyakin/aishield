package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/balyakin/aishield/internal/config"
	"github.com/balyakin/aishield/internal/policy"
)

func TestNotifySendsGenericWebhook(t *testing.T) {
	var payload Event
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", request.Method)
		}
		if request.Header.Get("Authorization") != "Bearer test" {
			t.Fatalf("missing auth header")
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode payload: %s", err)
		}
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})}

	notifier := NewWithClient(config.NotificationsConfig{
		Enabled: true,
		Webhook: config.WebhookConfig{
			URL:       "https://example.test/webhook",
			Headers:   map[string]string{"Authorization": "Bearer test"},
			OnBlocked: true,
		},
	}, client)

	err := notifier.Notify(context.Background(), Event{
		EventType: EventBlocked,
		Command:   "rm -rf /tmp/test",
		Severity:  policy.SeverityCritical,
	})

	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if payload.Command != "rm -rf /tmp/test" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestNotifySkipsDisabledEvents(t *testing.T) {
	called := false
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})}

	notifier := NewWithClient(config.NotificationsConfig{
		Enabled: true,
		Webhook: config.WebhookConfig{
			URL:      "https://example.test/webhook",
			OnWarned: false,
		},
	}, client)

	err := notifier.Notify(context.Background(), Event{
		EventType: EventWarned,
		Severity:  policy.SeverityWarn,
	})

	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if called {
		t.Fatal("expected disabled warned event to be skipped")
	}
}

func TestNotifyPIIFoundHonorsMinCount(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})}

	notifier := NewWithClient(config.NotificationsConfig{
		Enabled: true,
		Webhook: config.WebhookConfig{
			URL:         "https://example.test/webhook",
			OnPIIFound:  true,
			MinPIICount: 2,
		},
	}, client)

	if err := notifier.Notify(context.Background(), Event{EventType: EventPIIFound, Severity: policy.SeverityWarn, Count: 1}); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if err := notifier.Notify(context.Background(), Event{EventType: EventPIIFound, Severity: policy.SeverityWarn, Count: 2}); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if calls != 1 {
		t.Fatalf("expected exactly one PII notification, got %d", calls)
	}
}

type roundTripFunc func(request *http.Request) (*http.Response, error)

func (roundTripper roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTripper(request)
}
