package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/balyakin/aishield/internal/exitcode"
)

func newShareCommand() *cobra.Command {
	var logFile string
	var format string
	var clip bool

	shareCommand := &cobra.Command{
		Use:   "share [session-id|last]",
		Short: "Generate a shareable stats card",
		RunE: func(cmd *cobra.Command, args []string) error {
			stats, err := collectStats(logFile, 365*24*time.Hour)
			if err != nil {
				return exitcode.New(exitcode.RuntimeError, err.Error())
			}
			card := renderShareCard(stats, format)
			fmt.Print(card)
			if clip {
				if err := copyToClipboard(card); err != nil {
					fmt.Fprintf(os.Stderr, "Clipboard copy failed: %s\n", err)
				} else {
					fmt.Println("Copied to clipboard")
				}
			}
			return nil
		},
	}

	shareCommand.Flags().StringVarP(&logFile, "log-file", "l", "aishield.log", "Path to log file")
	shareCommand.Flags().StringVar(&format, "format", "ascii", "Format: ascii, markdown, text")
	shareCommand.Flags().BoolVar(&clip, "clip", true, "Copy to clipboard")
	return shareCommand
}

func renderShareCard(stats logStats, format string) string {
	topBlock := topMapItem(stats.BlockedCommands).Command
	if topBlock == "" {
		topBlock = "none"
	}
	topAgent := topMapItem(stats.Agents).Command
	if topAgent == "" {
		topAgent = "unknown"
	}

	if format == "markdown" {
		return fmt.Sprintf(
			"### aishield Stats\n\n- Blocked: %d\n- Warned: %d\n- Secrets masked: %d\n- Top block: `%s`\n- Agent: `%s`\n\n#aishield #aiSafety #devtools\n",
			stats.Blocked,
			stats.Warned,
			stats.SecretsMasked,
			topBlock,
			topAgent,
		)
	}
	return fmt.Sprintf(
		"+------------------------------------------+\n"+
			"|              aishield Stats              |\n"+
			"+------------------------------------------+\n"+
			"| Blocked:        %-24d|\n"+
			"| Warned:         %-24d|\n"+
			"| Secrets masked: %-24d|\n"+
			"| Top block:      %-24.24s|\n"+
			"| Agent:          %-24.24s|\n"+
			"| #aishield #aiSafety #devtools            |\n"+
			"+------------------------------------------+\n",
		stats.Blocked,
		stats.Warned,
		stats.SecretsMasked,
		topBlock,
		topAgent,
	)
}

type topCommand struct {
	Command string
	Count   int
}

func topMapItem(values map[string]int) topCommand {
	var result topCommand
	for command, count := range values {
		if count > result.Count {
			result = topCommand{Command: command, Count: count}
		}
	}
	return result
}

func copyToClipboard(value string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("pbcopy")
	case "linux":
		command = exec.Command("wl-copy")
	default:
		return fmt.Errorf("unsupported clipboard platform %s", runtime.GOOS)
	}

	command.Stdin = bytes.NewBufferString(value)
	if err := command.Run(); err == nil {
		return nil
	}

	if runtime.GOOS != "linux" {
		return fmt.Errorf("clipboard command failed")
	}

	fallback := exec.Command("xclip", "-selection", "clipboard")
	fallback.Stdin = bytes.NewBufferString(value)
	return fallback.Run()
}
