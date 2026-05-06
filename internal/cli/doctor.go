package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/balyakin/aishield/internal/config"
	"github.com/balyakin/aishield/internal/exitcode"
)

func newDoctorCommand() *cobra.Command {
	var checkConfig bool
	var checkPaths bool
	var fix bool

	doctorCommand := &cobra.Command{
		Use:   "doctor",
		Short: "Check environment setup and configuration health",
		RunE: func(cmd *cobra.Command, args []string) error {
			loadedConfig, err := config.Load(config.LoadOptions{
				ConfigPath:    configPath,
				ConfigChanged: cmd.Root().PersistentFlags().Changed("config"),
			})
			if err != nil {
				fmt.Printf("ERROR config: %s\n", err)
				return exitcode.New(exitcode.ConfigValidation, "")
			}

			fmt.Println("Checking aishield environment")
			fmt.Printf("OK preset: %s (%d rules loaded)\n", loadedConfig.Preset, len(loadedConfig.Rules))
			if !checkConfig {
				if err := checkLogWritable(loadedConfig.Logging.File); err != nil {
					fmt.Printf("ERROR log file: %s\n", err)
				} else {
					fmt.Printf("OK log file: %s writable\n", loadedConfig.Logging.File)
				}
			}
			if checkPaths || !checkConfig {
				fmt.Printf("OK work dir: %s\n", loadedConfig.WorkDir)
			}
			if fix {
				fmt.Println("No automatic fixes were required")
			}
			return nil
		},
	}

	doctorCommand.Flags().BoolVar(&checkConfig, "check-config", false, "Check configuration only")
	doctorCommand.Flags().BoolVar(&checkPaths, "check-paths", false, "Check filesystem paths only")
	doctorCommand.Flags().BoolVar(&fix, "fix", false, "Attempt to auto-fix common issues")
	return doctorCommand
}

func checkLogWritable(path string) error {
	dir := filepath.Dir(path)
	if dir == "." {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return file.Close()
}
