package dashboard

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDashboardHealthAndStats(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "aishield.log")
	line := `{"schema_version":2,"ts":"2026-05-10T00:00:00Z","event_id":"evt1","session_id":"ses1","type":"decision","decision":"warn","pii_counts":{"EMAIL":1},"raw_masked":"[PII:EMAIL]"}` + "\n"
	if err := os.WriteFile(logPath, []byte(line), 0o600); err != nil {
		t.Fatalf("failed to write log: %s", err)
	}
	server, err := New(Options{LogFile: logPath, Listen: "127.0.0.1:0", Version: "test", EnabledPIIEntities: 18})
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	handler := server.Handler()

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"version":"test"`) {
		t.Fatalf("unexpected health response: %d %s", health.Code, health.Body.String())
	}

	stats := httptest.NewRecorder()
	handler.ServeHTTP(stats, httptest.NewRequest(http.MethodGet, "/api/stats?since=200000h", nil))
	if stats.Code != http.StatusOK || !strings.Contains(stats.Body.String(), `"EMAIL":1`) {
		t.Fatalf("unexpected stats response: %d %s", stats.Code, stats.Body.String())
	}
}

func TestDashboardRejectsNonLoopbackWithoutPassword(t *testing.T) {
	_, err := New(Options{LogFile: "aishield.log", Listen: "0.0.0.0:17891"})
	if err == nil {
		t.Fatal("expected non-loopback listen without password to fail")
	}
}

func TestDashboardAllowsIPv6LoopbackWithoutPassword(t *testing.T) {
	if _, err := New(Options{LogFile: "aishield.log", Listen: "[::1]:17891"}); err != nil {
		t.Fatalf("expected IPv6 loopback to be allowed: %s", err)
	}
}

func TestDashboardBasicAuth(t *testing.T) {
	server, err := New(Options{LogFile: "aishield.log", Listen: "127.0.0.1:0", Password: "secret"})
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
	}
	handler := server.Handler()

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", unauthorized.Code)
	}

	authorized := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	request.SetBasicAuth("aishield", "secret")
	handler.ServeHTTP(authorized, request)
	if authorized.Code != http.StatusOK {
		t.Fatalf("expected ok, got %d %s", authorized.Code, authorized.Body.String())
	}
}
