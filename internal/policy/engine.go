package policy

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/balyakin/aishield/internal/parser"
	"github.com/balyakin/aishield/internal/pathmatch"
)

type Engine struct {
	rules           []compiledRule
	defaultDecision Decision
	workDir         string
}

type compiledRule struct {
	rule        Rule
	order       int
	rawRegexes  []*regexp.Regexp
	argsRegexes []*regexp.Regexp
}

func NewEngine(rules []Rule, defaultDecision Decision, workDir string) (*Engine, error) {
	compiledRules := make([]compiledRule, 0, len(rules))
	for order, rule := range rules {
		compiledRule, err := compileRule(rule, order)
		if err != nil {
			return nil, err
		}
		compiledRules = append(compiledRules, compiledRule)
	}

	return &Engine{
		rules:           compiledRules,
		defaultDecision: defaultDecision,
		workDir:         workDir,
	}, nil
}

func (engine *Engine) Evaluate(command parser.ParsedCommand) EvalResult {
	matchedRules := make([]compiledRule, 0)
	for _, rule := range engine.rules {
		if rule.matches(command, engine.workDir) {
			matchedRules = append(matchedRules, rule)
		}
	}

	if len(matchedRules) == 0 {
		return EvalResult{
			Decision: engine.defaultDecision,
			Severity: severityForDecision(engine.defaultDecision),
			Reason:   "default action",
		}
	}

	winner := matchedRules[0]
	for _, candidate := range matchedRules[1:] {
		if candidate.isStrongerThan(winner) {
			winner = candidate
		}
	}

	names := make([]string, 0, len(matchedRules))
	for _, rule := range matchedRules {
		names = append(names, rule.rule.Name)
	}

	return EvalResult{
		Decision:     winner.rule.Decision,
		Rule:         winner.rule.Name,
		MatchedRules: names,
		Severity:     ruleSeverity(winner.rule),
		Reason:       ruleReason(winner.rule),
	}
}

func compileRule(rule Rule, order int) (compiledRule, error) {
	rawRegexes, err := compileRegexes(rule.Match.RawRegex, rule.Name, "raw_regex")
	if err != nil {
		return compiledRule{}, err
	}

	argsRegexes, err := compileRegexes(rule.Match.ArgsRegex, rule.Name, "args_regex")
	if err != nil {
		return compiledRule{}, err
	}

	return compiledRule{
		rule:        rule,
		order:       order,
		rawRegexes:  rawRegexes,
		argsRegexes: argsRegexes,
	}, nil
}

func compileRegexes(patterns []string, ruleName string, fieldName string) ([]*regexp.Regexp, error) {
	regexes := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %q has invalid %s %q: %w", ruleName, fieldName, pattern, err)
		}
		regexes = append(regexes, regex)
	}
	return regexes, nil
}

func (rule compiledRule) matches(command parser.ParsedCommand, workDir string) bool {
	criteria := rule.rule.Match
	if len(criteria.Executables) > 0 && !matchesExecutable(command, criteria.Executables) {
		return false
	}
	if len(criteria.ArgsContain) > 0 && !matchesArgsContain(command, criteria.ArgsContain) {
		return false
	}
	if len(rule.argsRegexes) > 0 && !matchesRegexes(joinArgs(command), rule.argsRegexes) {
		return false
	}
	if len(rule.rawRegexes) > 0 && !matchesRegexes(command.Raw, rule.rawRegexes) {
		return false
	}
	if len(criteria.FilePaths) > 0 && !matchesFilePaths(command, criteria.FilePaths, workDir) {
		return false
	}
	if criteria.HasSudo != nil && command.HasSudo != *criteria.HasSudo {
		return false
	}
	if len(criteria.EnvVarKeys) > 0 && !matchesEnvVars(command, criteria.EnvVarKeys) {
		return false
	}
	return true
}

func (rule compiledRule) isStrongerThan(other compiledRule) bool {
	ruleStrength := decisionStrength(rule.rule.Decision)
	otherStrength := decisionStrength(other.rule.Decision)
	if ruleStrength != otherStrength {
		return ruleStrength > otherStrength
	}
	if rule.rule.Priority != other.rule.Priority {
		return rule.rule.Priority < other.rule.Priority
	}
	return rule.order > other.order
}

func matchesExecutable(command parser.ParsedCommand, executables []string) bool {
	commands := commandSegments(command)
	for _, segment := range commands {
		for _, executable := range executables {
			if segment.Executable == executable {
				return true
			}
		}
	}
	return false
}

func matchesArgsContain(command parser.ParsedCommand, values []string) bool {
	joinedArgs := joinArgs(command)
	for _, value := range values {
		if strings.Contains(joinedArgs, value) {
			return true
		}
	}
	return false
}

func matchesRegexes(value string, regexes []*regexp.Regexp) bool {
	for _, regex := range regexes {
		if regex.MatchString(value) {
			return true
		}
	}
	return false
}

func matchesFilePaths(command parser.ParsedCommand, rules []PathRule, workDir string) bool {
	for _, filePath := range command.FilePaths {
		for _, rule := range rules {
			if pathmatch.Match(rule.Pattern, filePath, workDir) {
				return true
			}
		}
	}
	return false
}

func matchesEnvVars(command parser.ParsedCommand, keys []string) bool {
	for _, key := range keys {
		if _, ok := command.EnvVars[key]; ok {
			return true
		}
	}
	return false
}

func commandSegments(command parser.ParsedCommand) []parser.ParsedCommand {
	if len(command.Pipes) > 0 {
		return command.Pipes
	}
	return []parser.ParsedCommand{command}
}

func joinArgs(command parser.ParsedCommand) string {
	values := make([]string, 0)
	for _, segment := range commandSegments(command) {
		values = append(values, segment.Args...)
	}
	return strings.Join(values, " ")
}

func decisionStrength(decision Decision) int {
	switch decision {
	case Block:
		return 3
	case Warn:
		return 2
	default:
		return 1
	}
}

func severityForDecision(decision Decision) string {
	switch decision {
	case Block:
		return SeverityCritical
	case Warn:
		return SeverityWarn
	default:
		return SeverityInfo
	}
}

func ruleSeverity(rule Rule) string {
	if rule.Severity != "" {
		return rule.Severity
	}
	return severityForDecision(rule.Decision)
}

func ruleReason(rule Rule) string {
	if rule.Description != "" {
		return rule.Description
	}
	if rule.Name != "" {
		return rule.Name
	}
	return "matched rule"
}
