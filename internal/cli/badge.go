package cli

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
)

func newBadgeCommand() *cobra.Command {
	var style string
	var link string

	badgeCommand := &cobra.Command{
		Use:   "badge",
		Short: "Generate a markdown badge",
		Run: func(cmd *cobra.Command, args []string) {
			query := url.Values{}
			query.Set("logo", "shield")
			if style != "default" {
				query.Set("style", style)
			}
			badgeURL := "https://img.shields.io/badge/protected%20by-aishield-4c1?" + query.Encode()
			fmt.Printf("[![Protected by aishield](%s)](%s)\n", badgeURL, link)
		},
	}

	badgeCommand.Flags().StringVar(&style, "style", "default", "Badge style: default, flat, flat-square, for-the-badge")
	badgeCommand.Flags().StringVar(&link, "link", "https://github.com/balyakin/aishield", "Link for the badge")
	return badgeCommand
}
