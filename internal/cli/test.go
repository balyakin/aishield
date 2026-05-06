package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/balyakin/aishield/internal/exitcode"
)

func newTestCommand() *cobra.Command {
	var preset string
	var jsonOutput bool

	testCommand := &cobra.Command{
		Use:   "test [flags] -- <command> [args...]",
		Short: "Test a command against security policies",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			loadedConfig, err := loadConfig(cmd, preset, "", false)
			if err != nil {
				return exitcode.New(exitcode.ConfigValidation, err.Error())
			}

			decision, err := evaluateCommand(loadedConfig, strings.Join(args, " "))
			if err != nil {
				return exitcode.New(exitcode.RuntimeError, err.Error())
			}
			if jsonOutput {
				if err := printJSON(decision); err != nil {
					return err
				}
			} else {
				printDecision(decision)
			}
			return exitForDecision(decision.Result.Decision)
		},
	}

	testCommand.Flags().StringVarP(&preset, "preset", "p", "standard", "Security preset for the test")
	testCommand.Flags().BoolVar(&jsonOutput, "json", false, "Output result as JSON")
	return testCommand
}
