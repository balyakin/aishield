package env

import "testing"

func TestFilterBlocksVariables(t *testing.T) {
	values := []string{"PATH=/bin", "GITHUB_TOKEN=secret", "HOME=/tmp"}
	config := Config{BlockList: []string{"GITHUB_TOKEN"}}

	filtered := Filter(values, config)

	if Get(filtered, "GITHUB_TOKEN") != "" {
		t.Fatal("expected GITHUB_TOKEN to be blocked")
	}
	if Get(filtered, "PATH") != "/bin" {
		t.Fatalf("expected PATH to pass through, got %q", Get(filtered, "PATH"))
	}
}

func TestFilterRedactsVariables(t *testing.T) {
	values := []string{"DATABASE_URL=postgres://real-secret"}
	config := Config{RedactList: []string{"DATABASE_URL"}}

	filtered := Filter(values, config)

	if Get(filtered, "DATABASE_URL") != "postgres://user:***@localhost:5432/db" {
		t.Fatalf("unexpected redacted value: %q", Get(filtered, "DATABASE_URL"))
	}
}

func TestFilterAllowList(t *testing.T) {
	values := []string{"PATH=/bin", "HOME=/tmp", "USER=test"}
	config := Config{AllowList: []string{"PATH", "HOME"}}

	filtered := Filter(values, config)

	if Get(filtered, "USER") != "" {
		t.Fatal("expected USER to be removed by allow list")
	}
	if Get(filtered, "HOME") != "/tmp" {
		t.Fatalf("expected HOME to pass through, got %q", Get(filtered, "HOME"))
	}
}

func TestSetAddsAndReplacesVariables(t *testing.T) {
	values := []string{"PATH=/bin"}
	values = Set(values, "PATH", "/usr/bin")
	values = Set(values, "HOME", "/tmp")

	if Get(values, "PATH") != "/usr/bin" {
		t.Fatalf("unexpected PATH: %q", Get(values, "PATH"))
	}
	if Get(values, "HOME") != "/tmp" {
		t.Fatalf("unexpected HOME: %q", Get(values, "HOME"))
	}
}
