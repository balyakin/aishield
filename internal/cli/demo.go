package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/balyakin/aishield/internal/config"
)

func newDemoCommand() *cobra.Command {
	var jsonOutput bool

	demoCommand := &cobra.Command{
		Use:   "demo",
		Short: "Run a safe local demo",
		RunE: func(cmd *cobra.Command, args []string) error {
			loadedConfig := config.DefaultConfig()
			presetConfig, _ := config.PresetConfig("standard")
			loadedConfig = config.Merge(loadedConfig, presetConfig)
			masker, err := config.NewMasker(loadedConfig)
			if err != nil {
				return err
			}

			allowed, _ := evaluateCommand(loadedConfig, "ls -la")
			blocked, _ := evaluateCommand(loadedConfig, "rm -rf /tmp/aishield-demo")
			masked := masker.MaskString("API_KEY=sk-ant-api03-EXAMPLE12345678901234567890")

			result := map[string]interface{}{
				"allowed":        allowed.Result.Decision,
				"blocked":        blocked.Result.Decision,
				"masked_output":  masked.Value,
				"secrets_masked": len(masked.Counts),
			}
			if jsonOutput {
				return printJSON(result)
			}

			fmt.Println("Starting safe demo in /tmp/aishield-demo")
			fmt.Printf("Allowed: ls -la -> %s\n", allowed.Result.Decision)
			fmt.Printf("Blocked: rm -rf /tmp/aishield-demo -> %s (%s)\n", blocked.Result.Decision, blocked.Result.Rule)
			fmt.Printf("Masked: %s\n", masked.Value)
			fmt.Println("Demo complete: 1 allowed, 1 blocked, 1 secret masked")
			return nil
		},
	}

	demoCommand.Flags().BoolVar(&jsonOutput, "json", false, "Output demo events as JSON")
	return demoCommand
}
