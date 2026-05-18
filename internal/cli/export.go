package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/balyakin/aishield/internal/auditlog"
	"github.com/balyakin/aishield/internal/exitcode"
)

func newExportCommand() *cobra.Command {
	var logFile string
	var format string
	var fromValue string
	var toValue string
	var outputPath string

	exportCommand := &cobra.Command{
		Use:   "export",
		Short: "Export masked audit events as CSV or JSONL",
		RunE: func(cmd *cobra.Command, args []string) error {
			from, err := auditlog.ParseTimeParam(fromValue)
			if err != nil {
				return exitcode.New(exitcode.ConfigValidation, err.Error())
			}
			to, err := auditlog.ParseTimeParam(toValue)
			if err != nil {
				return exitcode.New(exitcode.ConfigValidation, err.Error())
			}
			writer := os.Stdout
			var tempPath string
			if outputPath != "" {
				file, err := os.CreateTemp(".", ".aishield-export-*")
				if err != nil {
					return exitcode.New(exitcode.RuntimeError, err.Error())
				}
				defer func() {
					_ = os.Remove(file.Name())
				}()
				writer = file
				tempPath = file.Name()
				defer func() {
					_ = file.Close()
				}()
			}
			filter := auditlog.Filter{From: from, To: to}
			switch format {
			case "csv":
				err = auditlog.ExportCSV(writer, logFile, filter)
			case "jsonl":
				err = auditlog.ExportJSONL(writer, logFile, filter)
			default:
				return exitcode.New(exitcode.ConfigValidation, "format must be csv or jsonl")
			}
			if err != nil {
				return exitcode.New(exitcode.RuntimeError, err.Error())
			}
			if outputPath != "" {
				if err := writer.Close(); err != nil {
					return exitcode.New(exitcode.RuntimeError, err.Error())
				}
				if err := os.Rename(tempPath, outputPath); err != nil {
					return exitcode.New(exitcode.RuntimeError, err.Error())
				}
			}
			return nil
		},
	}

	exportCommand.Flags().StringVarP(&logFile, "log-file", "l", "aishield.log", "Path to log file")
	exportCommand.Flags().StringVar(&format, "format", "csv", "Export format: csv or jsonl")
	exportCommand.Flags().StringVar(&fromValue, "from", "", "Start date/time, RFC3339 or YYYY-MM-DD")
	exportCommand.Flags().StringVar(&toValue, "to", "", "End date/time, RFC3339 or YYYY-MM-DD")
	exportCommand.Flags().StringVarP(&outputPath, "output", "o", "", "Write export to a file")
	return exportCommand
}
