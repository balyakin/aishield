package shell

import (
	"fmt"
	"os"
	"syscall"

	"github.com/balyakin/aishield/internal/config"
	"github.com/balyakin/aishield/internal/exitcode"
	"github.com/balyakin/aishield/internal/parser"
	"github.com/balyakin/aishield/internal/policy"
	"github.com/balyakin/aishield/internal/shim"
)

func Run(args []string) error {
	originalShell := os.Getenv(shim.EnvOriginalShell)
	if originalShell == "" {
		originalShell = "/bin/sh"
	}

	if len(args) >= 2 && args[0] == "-c" {
		evaluation, err := evaluateShellCommand(args[1])
		if err != nil {
			return err
		}
		if !evaluation.Allowed {
			_ = shim.NotifyDeniedForShell(evaluation)
			fmt.Fprintf(os.Stderr, "[aishield] BLOCKED: %s\n", args[1])
			fmt.Fprintf(os.Stderr, "Rule: %s\nReason: %s\n", evaluation.Result.Rule, evaluation.Result.Reason)
			return exitcode.New(evaluation.Code, "")
		}
	}

	execArgs := append([]string{originalShell}, args...)
	return syscall.Exec(originalShell, execArgs, os.Environ())
}

func evaluateShellCommand(raw string) (shim.Evaluation, error) {
	command := parser.Parse(raw)
	loadedConfig, err := config.Load(config.LoadOptions{
		Preset:         os.Getenv(shim.EnvPreset),
		PresetChanged:  os.Getenv(shim.EnvPreset) != "",
		ConfigPath:     os.Getenv(shim.EnvConfig),
		ConfigChanged:  os.Getenv(shim.EnvConfig) != "",
		LogFile:        os.Getenv(shim.EnvLogFile),
		LogFileChanged: os.Getenv(shim.EnvLogFile) != "",
	})
	if err != nil {
		return shim.Evaluation{}, exitcode.New(exitcode.ConfigValidation, err.Error())
	}

	engine, err := policy.NewEngine(loadedConfig.Rules, loadedConfig.DefaultAction, loadedConfig.WorkDir)
	if err != nil {
		return shim.Evaluation{}, err
	}

	result := engine.Evaluate(command)
	if os.Getenv(shim.EnvDryRun) == "true" {
		result.Decision = policy.Allow
	}
	allowed, code := shim.ResolveWrapperDecision(
		result,
		loadedConfig.WarnActionNonInteractive,
		shim.ConfirmTimeoutFromEnv(),
	)
	evaluation := shim.Evaluation{
		Command: command,
		Result:  result,
		Allowed: allowed,
		Code:    code,
		Config:  loadedConfig,
	}
	_ = shim.LogEvaluation("shell", "shell", evaluation)
	return evaluation, nil
}
