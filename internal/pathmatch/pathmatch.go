package pathmatch

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func Match(pattern string, value string, workDir string) bool {
	candidates := buildCandidates(value, workDir)
	patternCandidates := buildPatternCandidates(pattern, workDir)

	for _, patternCandidate := range patternCandidates {
		for _, candidate := range candidates {
			if matchCandidate(patternCandidate, candidate) {
				return true
			}
		}
	}
	return false
}

func buildCandidates(value string, workDir string) []string {
	expanded := expandHome(value)
	absolute := expanded
	if !filepath.IsAbs(expanded) {
		absolute = filepath.Join(workDir, expanded)
	}
	absolute = filepath.Clean(absolute)

	candidates := []string{
		filepath.ToSlash(absolute),
		filepath.ToSlash(expanded),
		filepath.Base(expanded),
	}

	relative, err := filepath.Rel(workDir, absolute)
	if err == nil {
		candidates = append(candidates, filepath.ToSlash(relative))
	}
	return candidates
}

func buildPatternCandidates(pattern string, workDir string) []string {
	expanded := expandHome(pattern)
	candidates := []string{
		filepath.ToSlash(expanded),
	}

	if !filepath.IsAbs(expanded) {
		candidates = append(candidates, filepath.ToSlash(filepath.Join(workDir, expanded)))
	}
	return candidates
}

func expandHome(value string) string {
	if value == "~" {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			return homeDir
		}
	}
	if strings.HasPrefix(value, "~/") {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(homeDir, strings.TrimPrefix(value, "~/"))
		}
	}
	return value
}

func matchCandidate(pattern string, value string) bool {
	regexText := globToRegex(filepath.ToSlash(filepath.Clean(pattern)))
	regex := regexp.MustCompile(regexText)
	return regex.MatchString(filepath.ToSlash(filepath.Clean(value)))
}

func globToRegex(pattern string) string {
	var builder strings.Builder
	builder.WriteString("^")

	for index := 0; index < len(pattern); index++ {
		character := pattern[index]
		if character == '*' {
			nextIndex := index + 1
			if nextIndex < len(pattern) && pattern[nextIndex] == '*' {
				builder.WriteString(".*")
				index = nextIndex
				continue
			}
			builder.WriteString("[^/]*")
			continue
		}
		if character == '?' {
			builder.WriteString("[^/]")
			continue
		}
		builder.WriteString(regexp.QuoteMeta(string(character)))
	}

	builder.WriteString("$")
	return builder.String()
}
