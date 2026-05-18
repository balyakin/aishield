package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/balyakin/aishield/internal/config"
	"github.com/balyakin/aishield/internal/dataprotection"
	"github.com/balyakin/aishield/internal/exitcode"
	"github.com/balyakin/aishield/internal/logger"
	"github.com/balyakin/aishield/internal/pii"
)

func newScanCommand() *cobra.Command {
	var text string
	var filePath string
	var replacementMode string
	var piiEnabled bool
	var jsonOutput bool
	var audit bool
	var logFile string

	scanCommand := &cobra.Command{
		Use:   "scan",
		Short: "Scan local text for PII and print masked output",
		RunE: func(cmd *cobra.Command, args []string) error {
			if text != "" && filePath != "" {
				return exitcode.New(exitcode.ConfigValidation, "--text and --file are mutually exclusive")
			}
			loadedConfig, err := loadConfig(cmd, "", logFile, false)
			if err != nil {
				return exitcode.New(exitcode.ConfigValidation, err.Error())
			}
			if replacementMode != "" {
				loadedConfig.PII.ReplacementMode = pii.ReplacementMode(replacementMode)
			}
			if cmd.Flags().Changed("pii-enabled") {
				loadedConfig.PII.Enabled = piiEnabled
			}
			input, err := readScanInput(text, filePath)
			if err != nil {
				return exitcode.New(exitcode.RuntimeError, err.Error())
			}
			protector, err := config.NewDataProtector(loadedConfig)
			if err != nil {
				return exitcode.New(exitcode.ConfigValidation, err.Error())
			}
			protectionResult := protector.ProtectString(input)
			result := scanResultFromProtection(protectionResult)
			if audit {
				if err := logScanEvent(loadedConfig, protectionResult); err != nil {
					return exitcode.New(exitcode.RuntimeError, err.Error())
				}
			}
			if jsonOutput {
				return printJSON(result)
			}
			fmt.Print(result.MaskedValue)
			return nil
		},
	}

	scanCommand.Flags().StringVar(&text, "text", "", "Text to scan")
	scanCommand.Flags().StringVar(&filePath, "file", "", "File to scan")
	scanCommand.Flags().StringVar(&replacementMode, "replacement-mode", "", "PII replacement mode: placeholder, fake, hash")
	scanCommand.Flags().BoolVar(&piiEnabled, "pii-enabled", true, "Enable PII scanning for this invocation")
	scanCommand.Flags().BoolVar(&jsonOutput, "json", false, "Output ScanResult JSON")
	scanCommand.Flags().BoolVar(&audit, "audit", false, "Write a sanitized scan event to the audit log")
	scanCommand.Flags().StringVarP(&logFile, "log-file", "l", "aishield.log", "Path to log file")
	return scanCommand
}

func readScanInput(text string, filePath string) (string, error) {
	if text != "" {
		return text, nil
	}
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		return string(data), err
	}
	data, err := io.ReadAll(os.Stdin)
	return string(data), err
}

func scanResultFromProtection(result dataprotection.Result) pii.ScanResult {
	metadata := map[string]interface{}{}
	if len(result.SecretCounts) > 0 {
		metadata["secret_counts"] = result.SecretCounts
		metadata["secret_total"] = result.Summary.SecretTotal
	}
	if result.Summary.CompositePII {
		metadata["composite_pii"] = true
	}
	if len(metadata) == 0 {
		metadata = nil
	}
	return pii.ScanResult{
		MaskedValue: result.Value,
		Changed:     result.Changed,
		Counts:      result.PIICounts,
		Findings:    result.PIIFindings,
		Metadata:    metadata,
	}
}

func logScanEvent(loadedConfig config.Config, result dataprotection.Result) error {
	protector, err := config.NewDataProtector(loadedConfig)
	if err != nil {
		return err
	}
	auditLogger, err := logger.NewProtected(loadedConfig.Logging.File, protector, "scan", loadedConfig.WorkDir)
	if err != nil {
		return err
	}
	defer func() {
		_ = auditLogger.Close()
	}()
	return auditLogger.Log(logger.Event{
		Backend:        "cli",
		Type:           "scan",
		TraceID:        logger.NewTraceID(),
		RawMasked:      result.Value,
		PIICounts:      result.PIICounts,
		PIIFindings:    result.PIIFindings,
		SecretCounts:   result.SecretCounts,
		DataProtection: &result.Summary,
		PreSanitized:   true,
	})
}
