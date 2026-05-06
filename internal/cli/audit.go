package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/balyakin/aishield/internal/config"
	"github.com/balyakin/aishield/internal/exitcode"
	"github.com/balyakin/aishield/internal/policy"
	"gopkg.in/yaml.v3"
)

func newAuditCommand() *cobra.Command {
	var logFile string
	var autoApply bool

	auditCommand := &cobra.Command{
		Use:   "audit",
		Short: "Analyze logs and suggest new security rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			stats, err := collectStats(logFile, 365*24*time.Hour)
			if err != nil {
				return exitcode.New(exitcode.RuntimeError, err.Error())
			}
			suggestions, err := auditSuggestions(logFile)
			if err != nil {
				return exitcode.New(exitcode.RuntimeError, err.Error())
			}
			fmt.Printf("Analyzed %d commands from %d sessions\n", stats.Commands, stats.Sessions)
			if len(suggestions) == 0 {
				fmt.Println("No concrete rule suggestions found yet")
			} else {
				fmt.Println("Suggestions:")
				for index, suggestion := range suggestions {
					fmt.Printf("  %d. Add to %s list: %s\n", index+1, suggestion.Decision, suggestion.Name)
					fmt.Printf("     Reason: %s\n", suggestion.Description)
				}
			}
			if autoApply && len(suggestions) > 0 {
				projectConfigPath := ".aishield.yaml"
				if configPath != "" {
					projectConfigPath = configPath
				}
				if err := appendSuggestedRules(projectConfigPath, suggestions); err != nil {
					return exitcode.New(exitcode.RuntimeError, err.Error())
				}
				fmt.Printf("Added %d suggested rule(s) to %s\n", len(suggestions), projectConfigPath)
			}
			return nil
		},
	}

	auditCommand.Flags().StringVarP(&logFile, "log-file", "l", "aishield.log", "Path to log file")
	auditCommand.Flags().BoolVar(&autoApply, "auto-apply", false, "Automatically add suggested rules to config")
	return auditCommand
}

func auditSuggestions(logFile string) ([]policy.Rule, error) {
	file, err := os.Open(logFile)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	rulesByName := make(map[string]policy.Rule)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		if event["type"] != "decision" {
			continue
		}
		rawCommand, _ := event["raw_masked"].(string)
		for _, rule := range suggestRulesForCommand(rawCommand) {
			rulesByName[rule.Name] = rule
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	rules := make([]policy.Rule, 0, len(rulesByName))
	for _, rule := range rulesByName {
		rules = append(rules, rule)
	}
	return rules, nil
}

func suggestRulesForCommand(rawCommand string) []policy.Rule {
	normalized := strings.ToLower(rawCommand)
	rules := make([]policy.Rule, 0)
	if strings.Contains(normalized, "terraform destroy") {
		rules = append(rules, policy.Rule{
			Name:        "warn-terraform-destroy",
			Description: "Warn before Terraform destroy",
			Decision:    policy.Warn,
			Severity:    policy.SeverityWarn,
			Match: policy.MatchCriteria{
				Executables: []string{"terraform"},
				ArgsContain: []string{"destroy"},
			},
		})
	}
	if strings.Contains(normalized, "kubectl delete") {
		rules = append(rules, policy.Rule{
			Name:        "block-kubectl-delete",
			Description: "Block Kubernetes resource deletion",
			Decision:    policy.Block,
			Severity:    policy.SeverityCritical,
			Match: policy.MatchCriteria{
				Executables: []string{"kubectl"},
				ArgsContain: []string{"delete"},
			},
		})
	}
	if strings.Contains(normalized, "docker system prune") || strings.Contains(normalized, "docker rm") {
		rules = append(rules, policy.Rule{
			Name:        "warn-docker-destructive",
			Description: "Warn before destructive Docker operations",
			Decision:    policy.Warn,
			Severity:    policy.SeverityWarn,
			Match: policy.MatchCriteria{
				Executables: []string{"docker"},
				ArgsContain: []string{"rm", "prune", "system prune"},
			},
		})
	}
	if strings.Contains(normalized, "| sh") || strings.Contains(normalized, "| bash") || strings.Contains(normalized, "| zsh") {
		rules = append(rules, policy.Rule{
			Name:        "block-pipe-to-shell",
			Description: "Block pipe-to-shell execution",
			Decision:    policy.Block,
			Severity:    policy.SeverityCritical,
			Match: policy.MatchCriteria{
				RawRegex: []string{`curl.*\|\s*(bash|sh|zsh)`, `wget.*\|\s*(bash|sh|zsh)`},
			},
		})
	}
	if strings.Contains(normalized, ".env") {
		rules = append(rules, policy.Rule{
			Name:        "block-env-file-access",
			Description: "Block direct access to environment secret files",
			Decision:    policy.Block,
			Severity:    policy.SeverityCritical,
			Match: policy.MatchCriteria{
				FilePaths: []policy.PathRule{
					{Pattern: ".env", Action: "any"},
					{Pattern: ".env.*", Action: "any"},
				},
			},
		})
	}
	return rules
}

func appendSuggestedRules(path string, rules []policy.Rule) error {
	rootNode, err := readProjectConfigNode(path)
	if err != nil {
		return err
	}

	rulesNode := getOrCreateRulesNode(rootNode)
	existingRules := existingRuleNames(rulesNode)
	for _, rule := range rules {
		if existingRules[rule.Name] {
			continue
		}
		ruleNode, err := marshalRuleNode(rule)
		if err != nil {
			return err
		}
		rulesNode.Content = append(rulesNode.Content, ruleNode)
		existingRules[rule.Name] = true
	}

	data, err := yaml.Marshal(rootNode)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func readProjectConfigNode(path string) (*yaml.Node, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		data = []byte("preset: " + config.DefaultPreset + "\nrules: []\n")
	} else if err != nil {
		return nil, err
	}

	var rootNode yaml.Node
	if err := yaml.Unmarshal(data, &rootNode); err != nil {
		return nil, err
	}
	if len(rootNode.Content) == 0 {
		rootNode.Kind = yaml.DocumentNode
		rootNode.Content = []*yaml.Node{{Kind: yaml.MappingNode}}
	}
	return &rootNode, nil
}

func getOrCreateRulesNode(rootNode *yaml.Node) *yaml.Node {
	mappingNode := rootNode.Content[0]
	for index := 0; index < len(mappingNode.Content); index += 2 {
		keyNode := mappingNode.Content[index]
		if keyNode.Value == "rules" {
			valueNode := mappingNode.Content[index+1]
			if valueNode.Kind != yaml.SequenceNode {
				valueNode.Kind = yaml.SequenceNode
				valueNode.Content = nil
			}
			return valueNode
		}
	}

	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "rules"}
	valueNode := &yaml.Node{Kind: yaml.SequenceNode}
	mappingNode.Content = append(mappingNode.Content, keyNode)
	mappingNode.Content = append(mappingNode.Content, valueNode)
	return valueNode
}

func existingRuleNames(rulesNode *yaml.Node) map[string]bool {
	names := make(map[string]bool)
	for _, ruleNode := range rulesNode.Content {
		for index := 0; index < len(ruleNode.Content); index += 2 {
			keyNode := ruleNode.Content[index]
			if keyNode.Value != "name" {
				continue
			}
			valueNode := ruleNode.Content[index+1]
			names[valueNode.Value] = true
		}
	}
	return names
}

func marshalRuleNode(rule policy.Rule) (*yaml.Node, error) {
	data, err := yaml.Marshal(rule)
	if err != nil {
		return nil, err
	}

	var rootNode yaml.Node
	if err := yaml.Unmarshal(data, &rootNode); err != nil {
		return nil, err
	}
	return rootNode.Content[0], nil
}
