package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/balyakin/aishield/internal/config"
	"github.com/balyakin/aishield/internal/exitcode"
	"github.com/balyakin/aishield/internal/secrets"
)

func newValidateCommand() *cobra.Command {
	var printEffectiveConfig bool
	var jsonOutput bool

	validateCommand := &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration and print effective policy",
		RunE: func(cmd *cobra.Command, args []string) error {
			loadedConfig, err := config.Load(config.LoadOptions{
				ConfigPath:    configPath,
				ConfigChanged: cmd.Root().PersistentFlags().Changed("config"),
			})
			if err != nil {
				return exitcode.New(exitcode.ConfigValidation, err.Error())
			}
			if printEffectiveConfig {
				data, err := config.Marshal(loadedConfig)
				if err != nil {
					return exitcode.New(exitcode.RuntimeError, err.Error())
				}
				fmt.Print(string(data))
				return nil
			}
			if jsonOutput {
				return printJSON(map[string]interface{}{
					"valid":           true,
					"preset":          loadedConfig.Preset,
					"rules_loaded":    len(loadedConfig.Rules),
					"secret_patterns": secretPatternCount(loadedConfig),
					"path_shims":      len(loadedConfig.Enforcement.ShimExecutables),
				})
			}
			fmt.Println("Config is valid")
			fmt.Printf("Preset: %s\n", loadedConfig.Preset)
			fmt.Printf("Rules loaded: %d\n", len(loadedConfig.Rules))
			fmt.Printf("Secret patterns: %d\n", secretPatternCount(loadedConfig))
			fmt.Printf("PATH shims: %d\n", len(loadedConfig.Enforcement.ShimExecutables))
			return nil
		},
	}

	validateCommand.Flags().BoolVar(&printEffectiveConfig, "print-effective-config", false, "Print merged effective config")
	validateCommand.Flags().BoolVar(&jsonOutput, "json", false, "Output result as JSON")
	return validateCommand
}

func secretPatternCount(loadedConfig config.Config) int {
	count := secrets.BuiltinPatternCount()
	count = count + len(loadedConfig.Secrets.CustomPatterns)
	if loadedConfig.Secrets.HighEntropy.Enabled {
		count++
	}
	if len(loadedConfig.Secrets.MaskStrings) > 0 {
		count++
	}
	return count
}
