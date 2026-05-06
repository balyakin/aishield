package cli

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/balyakin/aishield/internal/shell"
	"github.com/balyakin/aishield/internal/shim"
)

var (
	version    = "dev"
	commit     = "none"
	date       = "unknown"
	configPath string
	verbose    bool
)

func Execute() error {
	baseName := filepath.Base(os.Args[0])
	if baseName == "aishield-shell" {
		return shell.Run(os.Args[1:])
	}
	if baseName != "aishield" && os.Getenv(shim.EnvShimDir) != "" {
		return shim.Run(baseName, os.Args[1:])
	}

	rootCommand := newRootCommand()
	return rootCommand.Execute()
}

func newRootCommand() *cobra.Command {
	rootCommand := &cobra.Command{
		Use:           "aishield",
		Short:         "Local safety layer for AI agents",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCommand.PersistentFlags().StringVarP(&configPath, "config", "c", "", "Path to config file")
	rootCommand.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose debug output")

	rootCommand.AddCommand(newRunCommand())
	rootCommand.AddCommand(newInitCommand())
	rootCommand.AddCommand(newTestCommand())
	rootCommand.AddCommand(newValidateCommand())
	rootCommand.AddCommand(newDoctorCommand())
	rootCommand.AddCommand(newLogCommand())
	rootCommand.AddCommand(newDemoCommand())
	rootCommand.AddCommand(newVersionCommand())
	rootCommand.AddCommand(newCompletionCommand(rootCommand))
	rootCommand.AddCommand(newStatsCommand())
	rootCommand.AddCommand(newBadgeCommand())
	rootCommand.AddCommand(newShareCommand())
	rootCommand.AddCommand(newAuditCommand())
	rootCommand.AddCommand(newContribCommand())
	rootCommand.AddCommand(newInternalShimCommand())
	rootCommand.AddCommand(newInternalShellCommand())

	return rootCommand
}

func newInternalShimCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "__shim <target> [args...]",
		Hidden: true,
		Args:   cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return shim.Run(args[0], args[1:])
		},
	}
}

func newInternalShellCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "__shell [args...]",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return shell.Run(args)
		},
	}
}
