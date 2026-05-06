package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/balyakin/aishield/internal/exitcode"
)

func newLogCommand() *cobra.Command {
	var logFile string
	var eventType string
	var since time.Duration

	logCommand := &cobra.Command{
		Use:   "log",
		Short: "View and filter the aishield log file",
		RunE: func(cmd *cobra.Command, args []string) error {
			file, err := os.Open(logFile)
			if err != nil {
				return exitcode.New(exitcode.RuntimeError, err.Error())
			}
			defer func() {
				_ = file.Close()
			}()

			cutoff := time.Time{}
			if since > 0 {
				cutoff = time.Now().UTC().Add(-since)
			}

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if shouldPrintLogLine(line, eventType, cutoff) {
					fmt.Println(line)
				}
			}
			return scanner.Err()
		},
	}

	logCommand.Flags().StringVarP(&logFile, "log-file", "l", "aishield.log", "Path to log file")
	logCommand.Flags().StringVarP(&eventType, "type", "t", "", "Filter by event type")
	logCommand.Flags().DurationVar(&since, "since", 0, "Show events from the last duration")
	return logCommand
}

func shouldPrintLogLine(line string, eventType string, cutoff time.Time) bool {
	var event map[string]interface{}
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		return false
	}
	if eventType != "" && event["type"] != eventType {
		return false
	}
	if cutoff.IsZero() {
		return true
	}
	timestamp, ok := event["ts"].(string)
	if !ok {
		return false
	}
	parsedTime, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return false
	}
	return parsedTime.After(cutoff)
}
