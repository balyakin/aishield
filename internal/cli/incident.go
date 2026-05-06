package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/balyakin/aishield/internal/config"
)

type incident struct {
	Number  int    `json:"number"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
	Impact  string `json:"impact"`
	Source  string `json:"source"`
}

type incidentState struct {
	Date  string `json:"date"`
	Index int    `json:"index"`
}

var builtInIncidents = []incident{
	{
		Number:  1,
		Title:   "AI agent used a discovered production token",
		Summary: "An automation workflow found credentials in a local environment file and attempted production-adjacent destructive actions",
		Impact:  "Credential rotation and recovery work",
		Source:  "https://github.com/balyakin/aishield/tree/main/community-rules/incidents",
	},
	{
		Number:  2,
		Title:   "Autonomous cleanup targeted infrastructure resources",
		Summary: "A broad cleanup instruction was interpreted as permission to remove cloud resources without a second human confirmation",
		Impact:  "Service recovery and audit review",
		Source:  "https://github.com/balyakin/aishield/tree/main/community-rules/incidents",
	},
}

func printIncident(incidentConfig config.IncidentModeConfig) error {
	if !isIncidentOutputAllowed() {
		return nil
	}

	statePath, err := incidentStatePath()
	if err != nil {
		return err
	}

	state := readIncidentState(statePath)
	nowDate := time.Now().Format("2006-01-02")
	if incidentConfig.OncePerDay && state.Date == nowDate {
		return nil
	}

	index := nextIncidentIndex(state.Index)
	currentIncident := builtInIncidents[index]
	printIncidentCard(currentIncident)

	return writeIncidentState(statePath, incidentState{
		Date:  nowDate,
		Index: index,
	})
}

func isIncidentOutputAllowed() bool {
	if os.Getenv("CI") == "true" {
		return false
	}

	stdoutInfo, stdoutErr := os.Stdout.Stat()
	stderrInfo, stderrErr := os.Stderr.Stat()
	if stdoutErr != nil || stderrErr != nil {
		return false
	}
	if stdoutInfo.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return stderrInfo.Mode()&os.ModeCharDevice != 0
}

func printIncidentCard(currentIncident incident) {
	fmt.Printf("AI AGENT INCIDENT #%d\n", currentIncident.Number)
	fmt.Printf("Title: %s\n", currentIncident.Title)
	fmt.Printf("Summary: %s\n", currentIncident.Summary)
	fmt.Printf("Impact: %s\n", currentIncident.Impact)
	fmt.Printf("Source: %s\n", currentIncident.Source)
	fmt.Println("aishield would apply deterministic command policies, environment filtering, and audit logging.")
	fmt.Println()
}

func incidentStatePath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, ".aishield", "incident_state"), nil
}

func readIncidentState(path string) incidentState {
	data, err := os.ReadFile(path)
	if err != nil {
		return incidentState{Index: -1}
	}

	var state incidentState
	if err := json.Unmarshal(data, &state); err != nil {
		return incidentState{Index: -1}
	}
	return state
}

func writeIncidentState(path string, state incidentState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func nextIncidentIndex(previousIndex int) int {
	if len(builtInIncidents) == 0 {
		return 0
	}
	nextIndex := previousIndex + 1
	if nextIndex >= len(builtInIncidents) {
		return 0
	}
	return nextIndex
}
