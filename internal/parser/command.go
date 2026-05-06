package parser

import (
	"strings"
	"unicode"
)

type ParsedCommand struct {
	Raw        string            `json:"raw" yaml:"raw"`
	Executable string            `json:"executable" yaml:"executable"`
	Args       []string          `json:"args" yaml:"args"`
	Pipes      []ParsedCommand   `json:"pipes,omitempty" yaml:"pipes,omitempty"`
	IsShell    bool              `json:"is_shell" yaml:"is_shell"`
	FilePaths  []string          `json:"file_paths,omitempty" yaml:"file_paths,omitempty"`
	HasSudo    bool              `json:"has_sudo" yaml:"has_sudo"`
	EnvVars    map[string]string `json:"env_vars,omitempty" yaml:"env_vars,omitempty"`
}

var knownExecutables = map[string]bool{
	"apt": true, "apt-get": true, "aws": true, "az": true, "awk": true, "bash": true, "brew": true,
	"cargo": true, "cat": true, "chmod": true, "chown": true, "cmake": true, "command": true,
	"cp": true, "curl": true, "date": true, "dd": true, "diff": true, "docker": true, "echo": true,
	"file": true, "find": true, "ftp": true, "gcc": true, "gcloud": true, "git": true, "go": true,
	"grep": true, "head": true, "iptables": true, "javac": true, "kill": true, "kubectl": true,
	"less": true, "ls": true, "make": true, "man": true, "mkdir": true, "mkfs": true, "more": true,
	"mount": true, "mv": true, "nc": true, "ncat": true, "netcat": true, "node": true, "npm": true,
	"pnpm": true, "pip": true, "pkill": true, "printf": true, "pwd": true, "python": true, "python3": true,
	"railway": true, "rm": true, "rmdir": true, "rsync": true, "ruby": true, "rustc": true, "scp": true,
	"sed": true, "sh": true, "sort": true, "ssh": true, "stat": true, "sudo": true, "systemctl": true,
	"tail": true, "tee": true, "telnet": true, "terraform": true, "umount": true, "uniq": true,
	"wc": true, "wget": true, "whereis": true, "which": true, "yarn": true, "zsh": true,
}

func Parse(raw string) ParsedCommand {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ParsedCommand{
			Raw:     raw,
			IsShell: false,
		}
	}

	segments := splitPipes(trimmed)
	if len(segments) > 1 {
		return parsePipeline(raw, segments)
	}

	return parseSegment(raw, trimmed)
}

func JoinCommand(executable string, args []string) string {
	values := make([]string, 0, len(args)+1)
	values = append(values, executable)
	values = append(values, args...)
	return strings.Join(values, " ")
}

func parsePipeline(raw string, segments []string) ParsedCommand {
	pipes := make([]ParsedCommand, 0, len(segments))
	for _, segment := range segments {
		parsedSegment := parseSegment(segment, segment)
		pipes = append(pipes, parsedSegment)
	}

	firstCommand := pipes[0]
	firstCommand.Raw = raw
	firstCommand.Pipes = pipes
	firstCommand.IsShell = hasShellSegment(pipes)
	firstCommand.FilePaths = mergeFilePaths(pipes)
	firstCommand.EnvVars = mergeEnvVars(pipes)
	firstCommand.HasSudo = hasSudoSegment(pipes)
	return firstCommand
}

func parseSegment(raw string, segment string) ParsedCommand {
	tokens := splitFields(segment)
	envVars := make(map[string]string)
	for len(tokens) > 0 && isEnvAssignment(tokens[0]) {
		key, value := splitEnvAssignment(tokens[0])
		envVars[key] = value
		tokens = tokens[1:]
	}

	if len(tokens) == 0 {
		return ParsedCommand{
			Raw:     raw,
			IsShell: false,
			EnvVars: emptyEnvVars(envVars),
		}
	}

	hasSudo := tokens[0] == "sudo"
	if hasSudo {
		tokens = tokens[1:]
	}

	if len(tokens) == 0 {
		return ParsedCommand{
			Raw:        raw,
			Executable: "sudo",
			IsShell:    true,
			HasSudo:    true,
			EnvVars:    emptyEnvVars(envVars),
		}
	}

	executable := tokens[0]
	args := tokens[1:]
	isShell := isRecognizedCommand(executable, envVars)
	filePaths := extractFilePaths(args)

	return ParsedCommand{
		Raw:        raw,
		Executable: executable,
		Args:       args,
		IsShell:    isShell,
		FilePaths:  filePaths,
		HasSudo:    hasSudo,
		EnvVars:    emptyEnvVars(envVars),
	}
}

func splitPipes(raw string) []string {
	var segments []string
	var current strings.Builder
	var quote rune
	escaped := false

	for _, char := range raw {
		if escaped {
			current.WriteRune(char)
			escaped = false
			continue
		}
		if char == '\\' {
			current.WriteRune(char)
			escaped = true
			continue
		}
		if quote != 0 {
			current.WriteRune(char)
			if char == quote {
				quote = 0
			}
			continue
		}
		if char == '\'' || char == '"' {
			quote = char
			current.WriteRune(char)
			continue
		}
		if char == '|' {
			segments = append(segments, strings.TrimSpace(current.String()))
			current.Reset()
			continue
		}
		current.WriteRune(char)
	}

	segments = append(segments, strings.TrimSpace(current.String()))
	return segments
}

func splitFields(raw string) []string {
	var fields []string
	var current strings.Builder
	var quote rune
	escaped := false

	for _, char := range raw {
		if escaped {
			current.WriteRune(char)
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if char == quote {
				quote = 0
				continue
			}
			current.WriteRune(char)
			continue
		}
		if char == '\'' || char == '"' {
			quote = char
			continue
		}
		if unicode.IsSpace(char) {
			appendField(&fields, &current)
			continue
		}
		current.WriteRune(char)
	}

	appendField(&fields, &current)
	return fields
}

func appendField(fields *[]string, current *strings.Builder) {
	if current.Len() == 0 {
		return
	}
	*fields = append(*fields, current.String())
	current.Reset()
}

func isEnvAssignment(token string) bool {
	separatorIndex := strings.Index(token, "=")
	if separatorIndex <= 0 {
		return false
	}

	key := token[:separatorIndex]
	for position, char := range key {
		if position == 0 && !isEnvKeyStart(char) {
			return false
		}
		if !isEnvKeyChar(char) {
			return false
		}
	}
	return true
}

func splitEnvAssignment(token string) (string, string) {
	separatorIndex := strings.Index(token, "=")
	key := token[:separatorIndex]
	value := token[separatorIndex+1:]
	return key, value
}

func isEnvKeyStart(char rune) bool {
	return char == '_' || unicode.IsLetter(char)
}

func isEnvKeyChar(char rune) bool {
	return char == '_' || unicode.IsLetter(char) || unicode.IsDigit(char)
}

func isRecognizedCommand(executable string, envVars map[string]string) bool {
	if executable == "" {
		return false
	}
	if strings.Contains(executable, "/") {
		return true
	}
	if knownExecutables[executable] {
		return true
	}
	return len(envVars) > 0
}

func extractFilePaths(args []string) []string {
	paths := make([]string, 0)
	for _, arg := range args {
		if isFilePath(arg) {
			paths = append(paths, arg)
		}
	}
	return paths
}

func isFilePath(value string) bool {
	if strings.Contains(value, "://") {
		return false
	}
	if strings.HasPrefix(value, "/") {
		return true
	}
	if strings.HasPrefix(value, "./") {
		return true
	}
	if strings.HasPrefix(value, "../") {
		return true
	}
	if strings.HasPrefix(value, "~") {
		return true
	}
	return strings.Contains(value, "/")
}

func hasShellSegment(commands []ParsedCommand) bool {
	for _, command := range commands {
		if command.IsShell {
			return true
		}
	}
	return false
}

func hasSudoSegment(commands []ParsedCommand) bool {
	for _, command := range commands {
		if command.HasSudo {
			return true
		}
	}
	return false
}

func mergeFilePaths(commands []ParsedCommand) []string {
	paths := make([]string, 0)
	for _, command := range commands {
		paths = append(paths, command.FilePaths...)
	}
	return paths
}

func mergeEnvVars(commands []ParsedCommand) map[string]string {
	result := make(map[string]string)
	for _, command := range commands {
		for key, value := range command.EnvVars {
			result[key] = value
		}
	}
	return emptyEnvVars(result)
}

func emptyEnvVars(envVars map[string]string) map[string]string {
	if len(envVars) == 0 {
		return nil
	}
	return envVars
}
