package auditlog

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExportCSVContainsMaskedCounts(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "aishield.log")
	line := `{"schema_version":2,"ts":"2026-05-10T00:00:00Z","event_id":"evt1","trace_id":"trc_1","session_id":"ses1","type":"decision","decision":"warn","severity":"warn","rule":"r1","matched_rules":["r1"],"pii_counts":{"EMAIL":1},"secret_counts":{"api-key":1},"raw_masked":"email=[PII:EMAIL]","msg":"masked"}` + "\n"
	if err := os.WriteFile(logPath, []byte(line), 0o600); err != nil {
		t.Fatalf("failed to write log: %s", err)
	}

	var buffer bytes.Buffer
	if err := ExportCSV(&buffer, logPath, Filter{}); err != nil {
		t.Fatalf("export failed: %s", err)
	}
	output := buffer.String()
	if !strings.Contains(output, `EMAIL`) || !strings.Contains(output, "[PII:EMAIL]") {
		t.Fatalf("csv missing masked counts: %s", output)
	}
	if strings.Contains(output, "john@example.com") {
		t.Fatalf("csv leaked original PII: %s", output)
	}
}

func TestRetentionPreviewAndApply(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "aishield.log")
	oldTime := time.Now().UTC().AddDate(0, 0, -120).Format(time.RFC3339)
	newTime := time.Now().UTC().Format(time.RFC3339)
	data := `{"schema_version":2,"ts":"` + oldTime + `","event_id":"old","type":"decision"}` + "\n" +
		`{"schema_version":2,"ts":"` + newTime + `","event_id":"new","type":"decision"}` + "\n"
	if err := os.WriteFile(logPath, []byte(data), 0o600); err != nil {
		t.Fatalf("failed to write log: %s", err)
	}

	preview, err := RetentionPreview(logPath, 90)
	if err != nil {
		t.Fatalf("preview failed: %s", err)
	}
	if preview.Removed != 1 || preview.Retained != 1 {
		t.Fatalf("unexpected preview: %#v", preview)
	}
	before, _ := os.ReadFile(logPath)
	if string(before) != data {
		t.Fatal("preview modified log file")
	}

	applied, err := RetentionApply(logPath, 90, true)
	if err != nil {
		t.Fatalf("apply failed: %s", err)
	}
	if applied.Removed != 1 || applied.Retained != 1 || applied.ArchivePath == "" {
		t.Fatalf("unexpected apply report: %#v", applied)
	}
	after, _ := os.ReadFile(logPath)
	if strings.Contains(string(after), `"event_id":"old"`) || !strings.Contains(string(after), `"event_id":"new"`) {
		t.Fatalf("retention did not preserve retained events: %s", string(after))
	}
}

func TestCollectStatsDoesNotDoubleCountSecretCounts(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "aishield.log")
	line := `{"schema_version":2,"ts":"2026-05-10T00:00:00Z","event_id":"evt1","type":"secret_masked","secret_counts":{"api-key":2}}` + "\n" +
		`{"schema_version":2,"ts":"2026-05-10T00:00:01Z","event_id":"evt2","type":"pii_masked","pii_counts":{"EMAIL":3}}` + "\n"
	if err := os.WriteFile(logPath, []byte(line), 0o600); err != nil {
		t.Fatalf("failed to write log: %s", err)
	}

	stats, err := CollectStats(logPath, 24*365*time.Hour)
	if err != nil {
		t.Fatalf("collect stats failed: %s", err)
	}
	if stats.SecretsMasked != 2 {
		t.Fatalf("expected two secret masks, got %d", stats.SecretsMasked)
	}
	if stats.PIIMasked != 1 || stats.PIITotal != 3 {
		t.Fatalf("unexpected PII stats: %#v", stats)
	}
}
