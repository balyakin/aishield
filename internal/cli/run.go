package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/balyakin/aishield/internal/config"
	projectenv "github.com/balyakin/aishield/internal/env"
	"github.com/balyakin/aishield/internal/exitcode"
	"github.com/balyakin/aishield/internal/fsguard"
	projectlogger "github.com/balyakin/aishield/internal/logger"
	"github.com/balyakin/aishield/internal/notifier"
	"github.com/balyakin/aishield/internal/policy"
	"github.com/balyakin/aishield/internal/proxy"
	"github.com/balyakin/aishield/internal/shim"
)

func newRunCommand() *cobra.Command {
	var preset string
	var dryRun bool
	var logFile string
	var noMask bool
	var confirmTimeout time.Duration
	var incident bool

	runCommand := &cobra.Command{
		Use:   "run [flags] -- <command> [args...]",
		Short: "Run a command with aishield protection",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			loadedConfig, err := loadConfig(cmd, preset, logFile, noMask)
			if err != nil {
				return exitcode.New(exitcode.ConfigValidation, err.Error())
			}
			if incident || loadedConfig.IncidentMode.Enabled {
				if err := printIncident(loadedConfig.IncidentMode); err != nil {
					return exitcode.New(exitcode.RuntimeError, err.Error())
				}
			}
			return runProtectedCommand(loadedConfig, args, dryRun, confirmTimeout)
		},
	}

	runCommand.Flags().StringVarP(&preset, "preset", "p", "standard", "Security preset: strict, standard, permissive")
	runCommand.Flags().BoolVarP(&dryRun, "dry-run", "d", false, "Log only, do not block anything")
	runCommand.Flags().StringVarP(&logFile, "log-file", "l", "aishield.log", "Path to log file")
	runCommand.Flags().BoolVar(&noMask, "no-mask", false, "Disable secret masking")
	runCommand.Flags().DurationVar(&confirmTimeout, "confirm-timeout", 30*time.Second, "Timeout for user confirmations")
	runCommand.Flags().BoolVar(&incident, "incident", false, "Show a verified AI-agent incident at session start")
	return runCommand
}

func runProtectedCommand(loadedConfig config.Config, args []string, dryRun bool, confirmTimeout time.Duration) error {
	masker, err := config.NewMasker(loadedConfig)
	if err != nil {
		return exitcode.New(exitcode.ConfigValidation, err.Error())
	}

	auditLogger, err := projectlogger.New(loadedConfig.Logging.File, masker, args[0], loadedConfig.WorkDir)
	if err != nil {
		return exitcode.New(exitcode.RuntimeError, err.Error())
	}
	defer func() {
		_ = auditLogger.Close()
	}()

	_ = auditLogger.Log(projectlogger.Event{
		Type:    "lifecycle",
		Backend: "cli",
		Message: "session started",
		Config: map[string]interface{}{
			"preset":   loadedConfig.Preset,
			"work_dir": loadedConfig.WorkDir,
		},
	})

	engine, err := policy.NewEngine(loadedConfig.Rules, loadedConfig.DefaultAction, loadedConfig.WorkDir)
	if err != nil {
		return exitcode.New(exitcode.ConfigValidation, err.Error())
	}

	guard := fsguard.NewGuard(
		loadedConfig.FileSystem.ReadOnly,
		loadedConfig.FileSystem.Blocked,
		loadedConfig.FileSystem.SecretFiles,
		loadedConfig.WorkDir,
	)

	processEnv, cleanup, err := buildProcessEnv(loadedConfig, dryRun, confirmTimeout, auditLogger.SessionID())
	if err != nil {
		return exitcode.New(exitcode.RuntimeError, err.Error())
	}
	defer cleanup()

	startedAt := time.Now()
	ptyProxy := proxy.New(proxy.Options{
		Command:    args,
		Env:        processEnv,
		WorkDir:    loadedConfig.WorkDir,
		Policy:     engine,
		Masker:     masker,
		FSGuard:    guard,
		Logger:     auditLogger,
		Notifier:   notifier.New(loadedConfig.Notifications),
		ConfirmTTL: confirmTimeout,
		WarnAction: loadedConfig.WarnActionNonInteractive,
		DryRun:     dryRun,
		LogOutput:  loadedConfig.Logging.LogOutput,
	})

	stats, childCode, runErr := ptyProxy.Run()
	duration := time.Since(startedAt)
	_ = auditLogger.Log(projectlogger.Event{
		Type:    "lifecycle",
		Backend: "cli",
		Message: "session ended",
		Summary: map[string]interface{}{
			"duration":       duration.String(),
			"commands":       stats.Commands,
			"allowed":        stats.Allowed,
			"warned":         stats.Warned,
			"blocked":        stats.Blocked,
			"secrets_masked": stats.SecretsMasked,
		},
	})

	printSummary(stats, duration, loadedConfig.Logging.File)
	if runErr != nil {
		return exitcode.New(exitcode.ChildProcessFailed, runErr.Error())
	}
	if childCode != exitcode.Success {
		return exitcode.New(exitcode.ChildProcessFailed, "")
	}
	return nil
}

func buildProcessEnv(
	loadedConfig config.Config,
	dryRun bool,
	confirmTimeout time.Duration,
	sessionID string,
) ([]string, func(), error) {
	originalPath := os.Getenv("PATH")
	processEnv := projectenv.Filter(os.Environ(), loadedConfig.Environment)
	cleanup := func() {}

	binaryPath, err := os.Executable()
	if err != nil {
		return nil, cleanup, err
	}
	binaryPath, err = filepath.EvalSymlinks(binaryPath)
	if err != nil {
		return nil, cleanup, err
	}

	if loadedConfig.Enforcement.PathShim || loadedConfig.Enforcement.ShellWrapper {
		shimExecutables := []string{}
		if loadedConfig.Enforcement.PathShim {
			shimExecutables = loadedConfig.Enforcement.ShimExecutables
		}
		layer, err := shim.CreateLayer(binaryPath, shimExecutables, loadedConfig.Enforcement.ShellWrapper)
		if err != nil {
			return nil, cleanup, err
		}
		cleanup = func() {
			_ = layer.Close()
		}
		processEnv = projectenv.Set(processEnv, shim.EnvShimDir, layer.Dir)
		if loadedConfig.Enforcement.PathShim {
			processEnv = projectenv.Set(processEnv, "PATH", layer.Dir+string(os.PathListSeparator)+originalPath)
		}
		if loadedConfig.Enforcement.ShellWrapper {
			processEnv = projectenv.Set(processEnv, "SHELL", filepath.Join(layer.Dir, "aishield-shell"))
		}
	}

	processEnv = projectenv.Set(processEnv, shim.EnvOriginalPath, originalPath)
	processEnv = projectenv.Set(processEnv, shim.EnvOriginalShell, os.Getenv("SHELL"))
	processEnv = projectenv.Set(processEnv, shim.EnvPreset, loadedConfig.Preset)
	processEnv = projectenv.Set(processEnv, shim.EnvLogFile, loadedConfig.Logging.File)
	processEnv = projectenv.Set(processEnv, shim.EnvDryRun, fmt.Sprintf("%t", dryRun))
	processEnv = projectenv.Set(processEnv, shim.EnvConfirmTimeout, confirmTimeout.String())
	processEnv = projectenv.Set(processEnv, shim.EnvSessionID, sessionID)
	if configPath != "" {
		processEnv = projectenv.Set(processEnv, shim.EnvConfig, configPath)
	}
	return processEnv, cleanup, nil
}

func printSummary(stats proxy.Stats, duration time.Duration, logFile string) {
	fmt.Println()
	fmt.Println("📊 [aishield] Session summary:")
	fmt.Printf("Duration: %s\n", duration.Round(time.Second))
	fmt.Printf("Commands intercepted: %d\n", stats.Commands)
	fmt.Printf("Allowed: %d\n", stats.Allowed)
	fmt.Printf("Warned (confirmed): %d\n", stats.Warned)
	fmt.Printf("Blocked: %d\n", stats.Blocked)
	fmt.Printf("Secrets masked: %d\n", stats.SecretsMasked)
	fmt.Printf("Log: %s\n", logFile)
}
