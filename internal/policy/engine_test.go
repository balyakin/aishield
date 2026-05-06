package policy

import (
	"testing"

	"github.com/balyakin/aishield/internal/parser"
)

func TestStrictPreset(t *testing.T) {
	engine := mustEngine(t, StrictRules(), Block)

	assertDecision(t, engine, "rm -rf /", Block)
	assertDecision(t, engine, "ls -la", Allow)
	assertDecision(t, engine, "curl https://example.com", Block)
}

func TestStandardPreset(t *testing.T) {
	engine := mustEngine(t, StandardRules(), Allow)

	assertDecision(t, engine, "rm -rf /tmp/test", Block)
	assertDecision(t, engine, "curl https://example.com", Warn)
	assertDecision(t, engine, "git push origin main", Warn)
	assertDecision(t, engine, "ls -la", Allow)
}

func TestPermissivePreset(t *testing.T) {
	engine := mustEngine(t, PermissiveRules(), Allow)

	assertDecision(t, engine, "rm -rf /tmp/test", Warn)
	assertDecision(t, engine, "ls -la", Allow)
}

func TestRulePriorityAndLoadOrder(t *testing.T) {
	rules := []Rule{
		{
			Name:     "warn-rm",
			Decision: Warn,
			Priority: 10,
			Match: MatchCriteria{
				Executables: []string{"rm"},
			},
		},
		{
			Name:     "block-rm",
			Decision: Block,
			Priority: 100,
			Match: MatchCriteria{
				Executables: []string{"rm"},
			},
		},
	}
	engine := mustEngine(t, rules, Allow)
	result := engine.Evaluate(parser.Parse("rm file"))

	if result.Decision != Block {
		t.Fatalf("expected block, got %s", result.Decision)
	}
	if result.Rule != "block-rm" {
		t.Fatalf("unexpected rule: %s", result.Rule)
	}
}

func mustEngine(t *testing.T, rules []Rule, defaultDecision Decision) *Engine {
	t.Helper()

	engine, err := NewEngine(rules, defaultDecision, "/tmp")
	if err != nil {
		t.Fatalf("failed to build engine: %s", err)
	}
	return engine
}

func assertDecision(t *testing.T, engine *Engine, raw string, expected Decision) {
	t.Helper()

	result := engine.Evaluate(parser.Parse(raw))
	if result.Decision != expected {
		t.Fatalf("command %q: expected %s, got %s (%s)", raw, expected, result.Decision, result.Rule)
	}
}
