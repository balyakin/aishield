package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/balyakin/aishield/internal/config"
	"github.com/balyakin/aishield/internal/exitcode"
	"github.com/balyakin/aishield/internal/fsguard"
	"github.com/balyakin/aishield/internal/parser"
	"github.com/balyakin/aishield/internal/policy"
)

type commandDecision struct {
	Command parser.ParsedCommand `json:"command"`
	Result  policy.EvalResult    `json:"result"`
}

func loadConfig(cmd *cobra.Command, preset string, logFile string, noMask bool) (config.Config, error) {
	presetChanged := false
	if cmd.Flags().Lookup("preset") != nil {
		presetChanged = cmd.Flags().Changed("preset")
	}
	logFileChanged := false
	if cmd.Flags().Lookup("log-file") != nil {
		logFileChanged = cmd.Flags().Changed("log-file")
	}
	options := config.LoadOptions{
		Preset:         preset,
		PresetChanged:  presetChanged,
		ConfigPath:     configPath,
		ConfigChanged:  cmd.Root().PersistentFlags().Changed("config"),
		LogFile:        logFile,
		LogFileChanged: logFileChanged,
		NoMask:         noMask,
	}
	return config.Load(options)
}

func evaluateCommand(loadedConfig config.Config, raw string) (commandDecision, error) {
	command := parser.Parse(raw)
	if !command.IsShell {
		return commandDecision{
			Command: command,
			Result: policy.EvalResult{
				Decision: policy.Allow,
				Severity: policy.SeverityInfo,
				Reason:   "not recognized as shell command",
			},
		}, nil
	}

	guard := fsguard.NewGuard(
		loadedConfig.FileSystem.ReadOnly,
		loadedConfig.FileSystem.Blocked,
		loadedConfig.FileSystem.SecretFiles,
		loadedConfig.WorkDir,
	)
	pathResult := guard.Check(command.FilePaths, fsguard.IsWriteCommand(command))
	if !pathResult.Allowed {
		return commandDecision{
			Command: command,
			Result: policy.EvalResult{
				Decision: policy.Block,
				Rule:     "filesystem-guard",
				Severity: policy.SeverityCritical,
				Reason:   pathResult.Reason,
			},
		}, nil
	}

	engine, err := policy.NewEngine(loadedConfig.Rules, loadedConfig.DefaultAction, loadedConfig.WorkDir)
	if err != nil {
		return commandDecision{}, err
	}
	protector, err := config.NewDataProtector(loadedConfig)
	if err != nil {
		return commandDecision{}, err
	}
	protectionResult := protector.ProtectString(command.Raw)
	policyContext := policy.PolicyContext{PIIFindings: make([]policy.PIIFinding, 0, len(protectionResult.PIIFindings))}
	for _, finding := range protectionResult.PIIFindings {
		policyContext.PIIFindings = append(policyContext.PIIFindings, policy.PIIFinding{
			Type:       finding.Type,
			Confidence: finding.Confidence,
		})
	}

	return commandDecision{
		Command: command,
		Result:  engine.EvaluateWithContext(command, policyContext),
	}, nil
}

func printDecision(decision commandDecision) {
	switch decision.Result.Decision {
	case policy.Block:
		fmt.Printf("BLOCKED by rule: %s\n", decision.Result.Rule)
	case policy.Warn:
		fmt.Printf("WARNING by rule: %s\n", decision.Result.Rule)
	default:
		fmt.Println("ALLOWED")
	}
	if decision.Result.Reason != "" {
		fmt.Printf("Reason: %s\n", decision.Result.Reason)
	}
	if len(decision.Result.MatchedRules) > 0 {
		fmt.Printf("Matched rules: %s\n", strings.Join(decision.Result.MatchedRules, ", "))
	}
}

func printJSON(value interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func exitForDecision(decision policy.Decision) error {
	switch decision {
	case policy.Block:
		return exitcode.New(exitcode.PolicyBlocked, "")
	default:
		return nil
	}
}
