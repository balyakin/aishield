package shim

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/balyakin/aishield/internal/config"
	"github.com/balyakin/aishield/internal/exitcode"
	"github.com/balyakin/aishield/internal/logger"
	"github.com/balyakin/aishield/internal/notifier"
	"github.com/balyakin/aishield/internal/parser"
	"github.com/balyakin/aishield/internal/policy"
)

type Evaluation struct {
	Command parser.ParsedCommand
	Result  policy.EvalResult
	Allowed bool
	Code    int
	Config  config.Config
	TraceID string
}

func Run(target string, args []string) error {
	evaluation, err := Evaluate(target, args)
	if err != nil {
		return err
	}
	_ = LogEvaluation("shim", target, evaluation)
	if !evaluation.Allowed {
		_ = notifyDenied(target, evaluation)
		fmt.Fprintf(os.Stderr, "[aishield] BLOCKED: %s\n", Masked(evaluation.Config, evaluation.Command.Raw))
		fmt.Fprintf(os.Stderr, "Rule: %s\nReason: %s\n", evaluation.Result.Rule, evaluation.Result.Reason)
		return exitcode.New(evaluation.Code, "")
	}

	realExecutable, err := FindRealExecutable(target, os.Getenv(EnvOriginalPath))
	if err != nil {
		return exitcode.New(exitcode.RuntimeError, err.Error())
	}

	execArgs := append([]string{realExecutable}, args...)
	return syscall.Exec(realExecutable, execArgs, os.Environ())
}

func Evaluate(target string, args []string) (Evaluation, error) {
	raw := parser.JoinCommand(target, args)
	command := parser.Parse(raw)

	loadedConfig, err := config.Load(config.LoadOptions{
		Preset:         os.Getenv(EnvPreset),
		PresetChanged:  os.Getenv(EnvPreset) != "",
		ConfigPath:     os.Getenv(EnvConfig),
		ConfigChanged:  os.Getenv(EnvConfig) != "",
		LogFile:        os.Getenv(EnvLogFile),
		LogFileChanged: os.Getenv(EnvLogFile) != "",
	})
	if err != nil {
		return Evaluation{}, exitcode.New(exitcode.ConfigValidation, err.Error())
	}

	engine, err := policy.NewEngine(loadedConfig.Rules, loadedConfig.DefaultAction, loadedConfig.WorkDir)
	if err != nil {
		return Evaluation{}, err
	}
	protector, err := config.NewDataProtector(loadedConfig)
	if err != nil {
		return Evaluation{}, err
	}
	protectionResult := protector.ProtectString(command.Raw)
	policyContext := policy.PolicyContext{PIIFindings: make([]policy.PIIFinding, 0, len(protectionResult.PIIFindings))}
	for _, finding := range protectionResult.PIIFindings {
		policyContext.PIIFindings = append(policyContext.PIIFindings, policy.PIIFinding{
			Type:       finding.Type,
			Confidence: finding.Confidence,
		})
	}

	result := engine.EvaluateWithContext(command, policyContext)
	if os.Getenv(EnvDryRun) == "true" {
		result.Decision = policy.Allow
	}

	allowed, code := ResolveWrapperDecision(result, loadedConfig.WarnActionNonInteractive, ConfirmTimeoutFromEnv())
	return Evaluation{
		Command: command,
		Result:  result,
		Allowed: allowed,
		Code:    code,
		Config:  loadedConfig,
		TraceID: logger.NewTraceID(),
	}, nil
}

func LogEvaluation(backend string, agent string, evaluation Evaluation) error {
	protector, err := config.NewDataProtector(evaluation.Config)
	if err != nil {
		return err
	}

	auditLogger, err := logger.NewProtectedWithSession(
		evaluation.Config.Logging.File,
		protector,
		agent,
		evaluation.Config.WorkDir,
		os.Getenv(EnvSessionID),
	)
	if err != nil {
		return err
	}
	defer func() {
		_ = auditLogger.Close()
	}()

	parsedCommand := evaluation.Command
	if err := auditLogger.Log(logger.Event{
		Backend:   backend,
		Type:      "command",
		TraceID:   evaluation.TraceID,
		RawMasked: evaluation.Command.Raw,
		Parsed:    &parsedCommand,
	}); err != nil {
		return err
	}
	return auditLogger.LogDecisionWithTrace(backend, evaluation.Command, evaluation.Result, evaluation.TraceID)
}

func notifyDenied(target string, evaluation Evaluation) error {
	if !evaluation.Config.Notifications.Enabled {
		return nil
	}
	return notifier.New(evaluation.Config.Notifications).Notify(context.Background(), notifier.Event{
		EventType:        notifier.EventBlocked,
		Command:          Masked(evaluation.Config, evaluation.Command.Raw),
		Rule:             evaluation.Result.Rule,
		Reason:           Masked(evaluation.Config, evaluation.Result.Reason),
		Agent:            target,
		Severity:         evaluation.Result.Severity,
		WorkingDirectory: evaluation.Config.WorkDir,
	})
}

func Masked(loadedConfig config.Config, value string) string {
	protector, err := config.NewDataProtector(loadedConfig)
	if err != nil {
		return value
	}
	return protector.ProtectString(value).Value
}

func NotifyDeniedForShell(evaluation Evaluation) error {
	return notifyDenied("shell", evaluation)
}

func FindRealExecutable(target string, originalPath string) (string, error) {
	if originalPath == "" {
		return "", fmt.Errorf("%s is not set", EnvOriginalPath)
	}

	for _, dir := range filepath.SplitList(originalPath) {
		candidate := filepath.Join(dir, target)
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		if info.Mode()&0o111 == 0 {
			continue
		}
		return candidate, nil
	}
	return "", fmt.Errorf("real executable %q not found in original PATH", target)
}

func ResolveWrapperDecision(
	result policy.EvalResult,
	warnAction policy.Decision,
	confirmTimeout time.Duration,
) (bool, int) {
	switch result.Decision {
	case policy.Allow:
		return true, exitcode.Success
	case policy.Block:
		return false, exitcode.PolicyBlocked
	case policy.Warn:
		if isInteractive() {
			if askConfirmation(result, confirmTimeout) {
				return true, exitcode.Success
			}
			return false, exitcode.ConfirmationRejected
		}
		if warnAction == policy.Allow {
			return true, exitcode.Success
		}
		return false, exitcode.PolicyBlocked
	default:
		return false, exitcode.RuntimeError
	}
}

func askConfirmation(result policy.EvalResult, confirmTimeout time.Duration) bool {
	fmt.Fprintf(os.Stderr, "[aishield] WARNING: %s\n", result.Reason)
	fmt.Fprint(os.Stderr, "Allow? [y/N]: ")

	answer := make(chan string, 1)
	go func() {
		reader := bufio.NewReader(os.Stdin)
		value, err := reader.ReadString('\n')
		if err != nil {
			answer <- ""
			return
		}
		answer <- value
	}()

	select {
	case value := <-answer:
		value = strings.TrimSpace(strings.ToLower(value))
		return value == "y" || value == "yes"
	case <-time.After(confirmTimeout):
		return false
	}
}

func ConfirmTimeoutFromEnv() time.Duration {
	value := os.Getenv(EnvConfirmTimeout)
	if value == "" {
		return 30 * time.Second
	}

	duration, err := time.ParseDuration(value)
	if err != nil {
		return 30 * time.Second
	}
	return duration
}

func isInteractive() bool {
	if os.Getenv("CI") == "true" {
		return false
	}

	stdinInfo, stdinErr := os.Stdin.Stat()
	stderrInfo, stderrErr := os.Stderr.Stat()
	if stdinErr != nil || stderrErr != nil {
		return false
	}
	return stdinInfo.Mode()&os.ModeCharDevice != 0 && stderrInfo.Mode()&os.ModeCharDevice != 0
}
