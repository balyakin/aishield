package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"

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

type logStats struct {
	Sessions        int
	Commands        int
	Allowed         int
	Warned          int
	Blocked         int
	SecretsMasked   int
	BlockedCommands map[string]int
	Agents          map[string]int
}

func collectStats(path string, since time.Duration) (logStats, error) {
	file, err := os.Open(path)
	if err != nil {
		return logStats{}, err
	}
	defer func() {
		_ = file.Close()
	}()

	stats := logStats{
		BlockedCommands: make(map[string]int),
		Agents:          make(map[string]int),
	}
	cutoff := time.Now().UTC().Add(-since)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		if !eventAfter(event, cutoff) {
			continue
		}
		switch event["type"] {
		case "lifecycle":
			if event["msg"] == "session started" {
				stats.Sessions++
			}
		case "decision":
			stats.Commands++
			agent, _ := event["agent"].(string)
			if agent != "" {
				stats.Agents[agent] = stats.Agents[agent] + 1
			}
			switch event["decision"] {
			case "allow":
				stats.Allowed++
			case "warn":
				stats.Warned++
			case "block":
				stats.Blocked++
				raw, _ := event["raw_masked"].(string)
				stats.BlockedCommands[raw] = stats.BlockedCommands[raw] + 1
			}
		case "secret_masked":
			stats.SecretsMasked++
		}
	}
	return stats, scanner.Err()
}

func printStats(stats logStats, topCount int, logFile string) {
	fmt.Println("aishield Stats")
	fmt.Printf("Total sessions: %d\n", stats.Sessions)
	fmt.Printf("Total commands: %d\n", stats.Commands)
	fmt.Printf("Allowed: %d\n", stats.Allowed)
	fmt.Printf("Warned: %d\n", stats.Warned)
	fmt.Printf("Blocked: %d\n", stats.Blocked)
	fmt.Printf("Secrets masked: %d\n", stats.SecretsMasked)
	fmt.Println("Top blocked commands:")
	for _, item := range topBlocked(stats.BlockedCommands, topCount) {
		fmt.Printf("  %s (%d)\n", item.Command, item.Count)
	}
	topAgent := topMapItem(stats.Agents)
	if topAgent.Command != "" {
		fmt.Printf("Top agent: %s (%d)\n", topAgent.Command, topAgent.Count)
	}
	fmt.Printf("Log file: %s\n", logFile)
}

type topCommand struct {
	Command string
	Count   int
}

func topBlocked(values map[string]int, limit int) []topCommand {
	items := make([]topCommand, 0, len(values))
	for command, count := range values {
		items = append(items, topCommand{Command: command, Count: count})
	}
	sort.Slice(items, func(left int, right int) bool {
		return items[left].Count > items[right].Count
	})
	if len(items) > limit {
		return items[:limit]
	}
	return items
}

func topMapItem(values map[string]int) topCommand {
	items := topBlocked(values, 1)
	if len(items) == 0 {
		return topCommand{}
	}
	return items[0]
}

func eventAfter(event map[string]interface{}, cutoff time.Time) bool {
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
