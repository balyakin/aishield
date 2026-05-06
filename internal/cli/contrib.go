package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/balyakin/aishield/internal/exitcode"
	"github.com/balyakin/aishield/internal/policy"
	"gopkg.in/yaml.v3"
)

func newContribCommand() *cobra.Command {
	contribCommand := &cobra.Command{
		Use:   "contrib",
		Short: "Install community-contributed rules",
	}
	contribCommand.AddCommand(newContribListCommand())
	contribCommand.AddCommand(newContribSearchCommand())
	contribCommand.AddCommand(newContribInfoCommand())
	contribCommand.AddCommand(newContribInstallCommand())
	return contribCommand
}

func newContribListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available community rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			rules, err := communityRules()
			if err != nil {
				return err
			}
			for _, rule := range rules {
				fmt.Println(rule)
			}
			return nil
		},
	}
}

func newContribSearchCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "search <keyword>",
		Short: "Search community rules by keyword",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rules, err := communityRules()
			if err != nil {
				return err
			}
			for _, rule := range rules {
				if strings.Contains(rule, args[0]) {
					fmt.Println(rule)
				}
			}
			return nil
		},
	}
}

func newContribInfoCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "info <rule>",
		Short: "Show details of a community rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(filepath.Join("community-rules", args[0]+".yaml"))
			if err != nil {
				return err
			}
			fmt.Print(string(data))
			return nil
		},
	}
}

func newContribInstallCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "install <rule>",
		Short: "Install a community rule into local config",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rules, err := readCommunityRule(args[0])
			if err != nil {
				return exitcode.New(exitcode.RuntimeError, err.Error())
			}
			projectConfigPath := ".aishield.yaml"
			if configPath != "" {
				projectConfigPath = configPath
			}
			if err := appendSuggestedRules(projectConfigPath, rules); err != nil {
				return exitcode.New(exitcode.RuntimeError, err.Error())
			}
			fmt.Printf("Installed %d rule(s) from community-rules/%s.yaml into %s\n", len(rules), args[0], projectConfigPath)
			return nil
		},
	}
}

func communityRules() ([]string, error) {
	entries, err := os.ReadDir("community-rules")
	if err != nil {
		return nil, err
	}
	rules := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".yaml") {
			rules = append(rules, strings.TrimSuffix(name, ".yaml"))
		}
	}
	return rules, nil
}

func readCommunityRule(name string) ([]policy.Rule, error) {
	data, err := os.ReadFile(filepath.Join("community-rules", name+".yaml"))
	if err != nil {
		return nil, err
	}

	var ruleFile struct {
		Rules []policy.Rule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &ruleFile); err != nil {
		return nil, err
	}
	if len(ruleFile.Rules) == 0 {
		return nil, fmt.Errorf("community rule %q has no rules", name)
	}
	return ruleFile.Rules, nil
}
