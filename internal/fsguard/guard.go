package fsguard

import (
	"path/filepath"
	"strings"

	"github.com/balyakin/aishield/internal/parser"
	"github.com/balyakin/aishield/internal/pathmatch"
)

type Guard struct {
	readOnlyPaths []string
	blockedPaths  []string
	secretFiles   []string
	workDir       string
}

type PathCheckResult struct {
	Allowed bool
	Reason  string
}

func NewGuard(readOnlyPaths []string, blockedPaths []string, secretFiles []string, workDir string) *Guard {
	return &Guard{
		readOnlyPaths: readOnlyPaths,
		blockedPaths:  blockedPaths,
		secretFiles:   secretFiles,
		workDir:       workDir,
	}
}

func (guard *Guard) Check(paths []string, isWrite bool) PathCheckResult {
	for _, filePath := range paths {
		absolutePath := guard.resolvePath(filePath)
		if guard.matchesAny(guard.secretFiles, absolutePath) {
			return PathCheckResult{
				Allowed: false,
				Reason:  "secret file access is blocked: " + filePath,
			}
		}
		if guard.matchesAny(guard.blockedPaths, absolutePath) {
			return PathCheckResult{
				Allowed: false,
				Reason:  "path is blocked: " + filePath,
			}
		}
		if isWrite && guard.matchesAny(guard.readOnlyPaths, absolutePath) {
			return PathCheckResult{
				Allowed: false,
				Reason:  "path is read-only: " + filePath,
			}
		}
	}

	return PathCheckResult{
		Allowed: true,
	}
}

func IsWriteCommand(command parser.ParsedCommand) bool {
	executable := command.Executable
	switch executable {
	case "rm", "rmdir", "mv", "cp", "chmod", "chown", "tee", "dd", "mkfs":
		return true
	default:
		return argsContainWriteRedirect(command.Args)
	}
}

func (guard *Guard) resolvePath(filePath string) string {
	if filepath.IsAbs(filePath) {
		return filepath.Clean(filePath)
	}
	return filepath.Clean(filepath.Join(guard.workDir, filePath))
}

func (guard *Guard) matchesAny(patterns []string, filePath string) bool {
	for _, pattern := range patterns {
		if pathmatch.Match(pattern, filePath, guard.workDir) {
			return true
		}
	}
	return false
}

func argsContainWriteRedirect(args []string) bool {
	for _, arg := range args {
		if arg == ">" || arg == ">>" {
			return true
		}
		if strings.HasPrefix(arg, ">") {
			return true
		}
	}
	return false
}
