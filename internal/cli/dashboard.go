package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/balyakin/aishield/internal/config"
	"github.com/balyakin/aishield/internal/dashboard"
	"github.com/balyakin/aishield/internal/exitcode"
	"github.com/balyakin/aishield/internal/pii"
)

func newDashboardCommand() *cobra.Command {
	var logFile string
	var listen string
	var password string

	dashboardCommand := &cobra.Command{
		Use:   "dashboard",
		Short: "Serve the local audit dashboard",
		RunE: func(cmd *cobra.Command, args []string) error {
			loadedConfig, err := loadConfig(cmd, "", logFile, false)
			if err != nil {
				return exitcode.New(exitcode.ConfigValidation, err.Error())
			}
			if listen != "" {
				loadedConfig.Dashboard.Listen = listen
			}
			passwordValue := password
			if passwordValue == "" && loadedConfig.Dashboard.PasswordEnv != "" {
				passwordValue = os.Getenv(loadedConfig.Dashboard.PasswordEnv)
			}
			if passwordValue == "" {
				passwordValue = loadedConfig.Dashboard.Password
			}
			server, err := dashboard.New(dashboard.Options{
				LogFile:            loadedConfig.Logging.File,
				Listen:             loadedConfig.Dashboard.Listen,
				Password:           passwordValue,
				PasswordEnv:        "",
				Version:            version,
				EnabledPIIEntities: enabledPIIEntityCount(loadedConfig),
			})
			if err != nil {
				return exitcode.New(exitcode.ConfigValidation, err.Error())
			}
			fmt.Printf("Dashboard listening on http://%s\n", loadedConfig.Dashboard.Listen)
			if err := server.ListenAndServe(); err != nil {
				return exitcode.New(exitcode.RuntimeError, err.Error())
			}
			return nil
		},
	}

	dashboardCommand.Flags().StringVarP(&logFile, "log-file", "l", "aishield.log", "Path to log file")
	dashboardCommand.Flags().StringVar(&listen, "listen", "", "Listen address")
	dashboardCommand.Flags().StringVar(&password, "password", "", "Basic Auth password")
	return dashboardCommand
}

func enabledPIIEntityCount(loadedConfig config.Config) int {
	if !loadedConfig.PII.Enabled {
		return 0
	}
	explicit := stringSet(loadedConfig.PII.EntityTypes)
	types := loadedConfig.PII.EntityTypes
	if len(types) == 0 {
		types = pii.MandatoryEntityTypes()
	}
	counted := make(map[string]bool)
	count := 0
	for _, entityType := range types {
		for _, activeType := range expandedEntityTypes(entityType, loadedConfig) {
			if counted[activeType] {
				continue
			}
			if secretLikeEntity(activeType) && !loadedConfig.Secrets.Enabled && !explicit[activeType] {
				continue
			}
			if !countryAllowsEntity(activeType, loadedConfig.PII.Countries) {
				continue
			}
			counted[activeType] = true
			count++
		}
	}
	return count
}

func expandedEntityTypes(entityType string, loadedConfig config.Config) []string {
	if entityType == "IBAN" && countryEnabled("DE", loadedConfig.PII.Countries) {
		return []string{"IBAN", "DE_IBAN"}
	}
	return []string{entityType}
}

func countryAllowsEntity(entityType string, countries []string) bool {
	switch entityType {
	case "NL_BSN":
		return countryEnabled("NL", countries)
	case "DE_IBAN":
		return countryEnabled("DE", countries)
	case "FR_NIR":
		return countryEnabled("FR", countries)
	case "ES_DNI", "ES_NIE":
		return countryEnabled("ES", countries)
	case "IT_CODICE_FISCALE":
		return countryEnabled("IT", countries)
	case "PL_PESEL":
		return countryEnabled("PL", countries)
	default:
		return countryEnabled("generic", countries)
	}
}

func countryEnabled(country string, countries []string) bool {
	if len(countries) == 0 {
		return true
	}
	for _, value := range countries {
		if value == country {
			return true
		}
	}
	return false
}

func secretLikeEntity(entityType string) bool {
	switch entityType {
	case "API_KEY", "PRIVATE_KEY", "DB_CONN_STRING", "JWT_TOKEN":
		return true
	default:
		return false
	}
}

func stringSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}
