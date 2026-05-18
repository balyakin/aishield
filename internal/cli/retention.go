package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/balyakin/aishield/internal/auditlog"
	"github.com/balyakin/aishield/internal/config"
	"github.com/balyakin/aishield/internal/exitcode"
)

func newRetentionCommand() *cobra.Command {
	var logFile string
	var days int
	var archive bool

	retentionCommand := &cobra.Command{
		Use:   "retention",
		Short: "Preview or apply audit log retention",
	}
	retentionCommand.PersistentFlags().StringVarP(&logFile, "log-file", "l", "aishield.log", "Path to log file")
	retentionCommand.PersistentFlags().IntVar(&days, "days", 0, "Retention window in days")
	retentionCommand.PersistentFlags().BoolVar(&archive, "archive", false, "Archive removed events before deleting")

	retentionCommand.AddCommand(&cobra.Command{
		Use:   "preview",
		Short: "Preview retention without modifying the log",
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := runRetention(cmd, logFile, days, archive, false)
			if err != nil {
				return err
			}
			printRetentionReport(report)
			return nil
		},
	})
	retentionCommand.AddCommand(&cobra.Command{
		Use:   "apply",
		Short: "Apply retention compaction",
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := runRetention(cmd, logFile, days, archive, true)
			if err != nil {
				return err
			}
			printRetentionReport(report)
			return nil
		},
	})
	return retentionCommand
}

func runRetention(cmd *cobra.Command, logFile string, days int, archive bool, apply bool) (auditlog.RetentionReport, error) {
	logFileChanged := flagChanged(cmd, "log-file")
	loadedConfig, err := config.Load(config.LoadOptions{
		ConfigPath:     configPath,
		ConfigChanged:  cmd.Root().PersistentFlags().Changed("config"),
		LogFile:        logFile,
		LogFileChanged: logFileChanged,
	})
	if err != nil {
		return auditlog.RetentionReport{}, exitcode.New(exitcode.ConfigValidation, err.Error())
	}
	if days == 0 {
		days = loadedConfig.Audit.RetentionDays
	}
	if days <= 0 {
		return auditlog.RetentionReport{}, exitcode.New(exitcode.ConfigValidation, "--days is required when audit.retention_days is 0")
	}
	if !flagChanged(cmd, "archive") {
		archive = loadedConfig.Audit.ArchiveBeforeDelete
	}
	if apply {
		report, err := auditlog.RetentionApply(loadedConfig.Logging.File, days, archive)
		if err != nil {
			return report, exitcode.New(exitcode.RuntimeError, err.Error())
		}
		return report, nil
	}
	report, err := auditlog.RetentionPreview(loadedConfig.Logging.File, days)
	if err != nil {
		return report, exitcode.New(exitcode.RuntimeError, err.Error())
	}
	return report, nil
}

func flagChanged(cmd *cobra.Command, name string) bool {
	if cmd.Flags().Lookup(name) != nil && cmd.Flags().Changed(name) {
		return true
	}
	if cmd.InheritedFlags().Lookup(name) != nil && cmd.InheritedFlags().Changed(name) {
		return true
	}
	return false
}

func printRetentionReport(report auditlog.RetentionReport) {
	fmt.Printf("Log file: %s\n", report.LogFile)
	fmt.Printf("Cutoff: %s\n", report.Cutoff)
	fmt.Printf("Would remove: %d\n", report.Removed)
	fmt.Printf("Retained: %d\n", report.Retained)
	if report.Applied {
		fmt.Println("Applied: true")
	}
	if report.ArchivePath != "" {
		fmt.Printf("Archive: %s\n", report.ArchivePath)
	}
}
