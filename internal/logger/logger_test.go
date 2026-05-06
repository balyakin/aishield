package logger

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/balyakin/aishield/internal/secrets"
)

func TestLoggerWritesSchemaAndMasksRawCommand(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "aishield.log")
	masker, err := secrets.NewMasker(secrets.Options{Enabled: true})
	if err != nil {
		t.Fatalf("failed to build masker: %s", err)
	}

	auditLogger, err := New(logPath, masker, "agent", tempDir)
	if err != nil {
		t.Fatalf("failed to create logger: %s", err)
	}
	if err := auditLogger.Log(Event{
		Type:      "command",
		RawMasked: "echo AKIAIOSFODNN7EXAMPLE",
	}); err != nil {
		t.Fatalf("failed to log event: %s", err)
	}
	if err := auditLogger.Close(); err != nil {
		t.Fatalf("failed to close logger: %s", err)
	}

	event := readFirstEvent(t, logPath)
	if event["schema_version"].(float64) != SchemaVersion {
		t.Fatalf("unexpected schema version: %#v", event["schema_version"])
	}
	if event["raw_masked"] != "echo [MASKED:aws-key]" {
		t.Fatalf("raw command was not masked: %#v", event["raw_masked"])
	}
	if event["session_id"] == "" || event["event_id"] == "" {
		t.Fatalf("expected stable ids: %#v", event)
	}
}

func readFirstEvent(t *testing.T, path string) map[string]interface{} {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open log: %s", err)
	}
	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		t.Fatal("expected one log line")
	}

	var event map[string]interface{}
	if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
		t.Fatalf("failed to decode log event: %s", err)
	}
	return event
}
