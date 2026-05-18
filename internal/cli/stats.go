package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/balyakin/aishield/internal/auditlog"
	"github.com/balyakin/aishield/internal/exitcode"
)

func newStatsCommand() *cobra.Command {
	var logFile string
	var since time.Duration
	var topCount int

	statsCommand := &cobra.Command{
		Use:   "stats",
		Short: "Display a terminal dashboard with log analytics",
		RunE: func(cmd *cobra.Command, args []string) error {
			stats, err := collectStats(logFile, since)
			if err != nil {
				return exitcode.New(exitcode.RuntimeError, err.Error())
			}
			printStats(stats, topCount, logFile)
			return nil
		},
	}

	statsCommand.Flags().StringVarP(&logFile, "log-file", "l", "aishield.log", "Path to log file")
	statsCommand.Flags().DurationVar(&since, "since", 168*time.Hour, "Analysis period")
	statsCommand.Flags().IntVar(&topCount, "top", 5, "Number of top items to show")
	return statsCommand
}

type logStats = auditlog.Stats

func collectStats(path string, since time.Duration) (logStats, error) {
	return auditlog.CollectStats(path, since)
}

func printStats(stats logStats, topCount int, logFile string) {
	fmt.Println("aishield Stats")
	fmt.Printf("Total sessions: %d\n", stats.Sessions)
	fmt.Printf("Total commands: %d\n", stats.Commands)
	fmt.Printf("Allowed: %d\n", stats.Allowed)
	fmt.Printf("Warned: %d\n", stats.Warned)
	fmt.Printf("Blocked: %d\n", stats.Blocked)
	fmt.Printf("Secrets masked: %d\n", stats.SecretsMasked)
	fmt.Printf("PII findings: %d\n", stats.PIITotal)
	fmt.Println("Top PII types:")
	for _, item := range auditlog.SortedCounts(stats.PIITypes, topCount) {
		fmt.Printf("  %s\n", item)
	}
	fmt.Println("Top triggered rules:")
	for _, item := range auditlog.SortedCounts(stats.TopRules, topCount) {
		fmt.Printf("  %s\n", item)
	}
	fmt.Printf("Log file: %s\n", logFile)
}
