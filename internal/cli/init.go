package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/balyakin/aishield/internal/config"
	"github.com/balyakin/aishield/internal/exitcode"
)

func newInitCommand() *cobra.Command {
	var preset string
	var force bool

	initCommand := &cobra.Command{
		Use:   "init",
		Short: "Generate a default .aishield.yaml config file",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !force && fileExists(".aishield.yaml") && !confirmOverwrite() {
				return exitcode.New(exitcode.ConfirmationRejected, "init cancelled")
			}
			if _, err := config.PresetConfig(preset); err != nil {
				return exitcode.New(exitcode.ConfigValidation, err.Error())
			}
			err := os.WriteFile(".aishield.yaml", []byte(config.DefaultYAML(preset)), 0o600)
			if err != nil {
				return exitcode.New(exitcode.RuntimeError, err.Error())
			}
			fmt.Println("Generated .aishield.yaml")
			return nil
		},
	}

	initCommand.Flags().StringVarP(&preset, "preset", "p", "standard", "Base preset for the config")
	initCommand.Flags().BoolVarP(&force, "force", "f", false, "Overwrite existing config file")
	return initCommand
}

func confirmOverwrite() bool {
	fmt.Print(".aishield.yaml already exists. Overwrite? [y/N]: ")
	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "y" || answer == "yes"
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
