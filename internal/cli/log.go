package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/balyakin/aishield/internal/auditlog"
	"github.com/balyakin/aishield/internal/exitcode"
)

func newLogCommand() *cobra.Command {
	var logFile string
	var eventType string
	var since time.Duration
	var traceID string
	var sessionID string
	var piiType string
	var minPIIConfidence string

	logCommand := &cobra.Command{
		Use:   "log",
		Short: "View and filter the aishield log file",
		RunE: func(cmd *cobra.Command, args []string) error {
			filter := auditlog.Filter{
				Type:             eventType,
				TraceID:          traceID,
				SessionID:        sessionID,
				PIIType:          piiType,
				MinPIIConfidence: minPIIConfidence,
			}
			if since > 0 {
				filter.From = time.Now().UTC().Add(-since)
			}
			result, err := auditlog.List(logFile, filter, auditlog.Page{Page: 1, PerPage: 500})
			if err != nil {
				return exitcode.New(exitcode.RuntimeError, err.Error())
			}
			for _, event := range result.Items {
				data, err := json.Marshal(event)
				if err != nil {
					return exitcode.New(exitcode.RuntimeError, err.Error())
				}
				fmt.Println(string(data))
			}
			return nil
		},
	}

	logCommand.Flags().StringVarP(&logFile, "log-file", "l", "aishield.log", "Path to log file")
	logCommand.Flags().StringVarP(&eventType, "type", "t", "", "Filter by event type")
	logCommand.Flags().DurationVar(&since, "since", 0, "Show events from the last duration")
	logCommand.Flags().StringVar(&traceID, "trace-id", "", "Filter by trace_id")
	logCommand.Flags().StringVar(&sessionID, "session-id", "", "Filter by session_id")
	logCommand.Flags().StringVar(&piiType, "pii-type", "", "Filter by PII entity type")
	logCommand.Flags().StringVar(&minPIIConfidence, "min-pii-confidence", "", "Filter by minimum PII confidence")
	return logCommand
}
