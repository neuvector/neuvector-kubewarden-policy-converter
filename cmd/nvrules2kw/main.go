/*
Copyright (c) 2025 SUSE LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/convert"

	"github.com/urfave/cli/v2"
)

const appDescription = `Examples:

# Fetch NeuVector Admission Control Rules and pipe them to nvrules2kw.
# For instructions on connecting to the REST API server, visit:
# https://open-docs.neuvector.com/configuration/console
curl -k \
  -H "Content-Type: application/json" \
  -H "X-Auth-Apikey: <API_KEY>" \
  "https://<API_SERVER_ADDRESS>/v1/admission/rules" | nvrules2kw --output policies.yaml

# Convert rules from a file and output to a file
nvrules2kw convert --rulefile ./rules/nvrules.json --output policies.yaml

# Show supported criteria
nvrules2kw support
`

func main() {
	var commands = []*cli.Command{
		{
			Name:  "convert",
			Usage: "Convert NeuVector rules to Kubewarden policies",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "rulefile",
					Usage: "Path to the NeuVector rules JSON file. If not specified, read from stdin.",
				},
				&cli.StringFlag{
					Name:  "policyserver",
					Value: "default",
					Usage: "Bound to Policy Server",
				},
				&cli.BoolFlag{
					Name:  "backgroundaudit",
					Usage: "Whether the policy is used in audit checks",
					Value: true,
				},
				&cli.StringFlag{
					Name:  "output",
					Usage: "Output file for the generated policy (default: stdout)",
				},
				&cli.StringFlag{
					Name:  "mode",
					Usage: "Execution mode of this policy, either \"protect\" or \"monitor\"",
					Value: "protect",
				},
			},
			Before: func(c *cli.Context) error {
				mode := c.String("mode")
				if mode != "protect" && mode != "monitor" {
					return fmt.Errorf("invalid mode: %s. Allowed values are \"protect\" or \"monitor\"", mode)
				}
				return nil
			},
			Action: func(c *cli.Context) error {
				ruleFile := c.String("rulefile")
				policyServer := c.String("policyserver")
				backgroundAudit := c.Bool("backgroundaudit")
				outputFile := c.String("output")
				mode := c.String("mode")

				var input io.Reader
				if ruleFile != "" {
					file, err := os.Open(ruleFile)
					if err != nil {
						return fmt.Errorf("error opening file: %w", err)
					}
					defer file.Close()
					input = file
				} else {
					stat, _ := os.Stdin.Stat()
					if (stat.Mode() & os.ModeCharDevice) == 0 {
						input = os.Stdin
					} else {
						cli.ShowCommandHelpAndExit(c, "convert", 1)
					}
				}

				converter := convert.NewRuleConverter(convert.ConversionConfig{
					OutputFile:      outputFile,
					Mode:            mode,
					PolicyServer:    policyServer,
					BackgroundAudit: backgroundAudit,
				})

				if err := converter.ProcessRules(input); err != nil {
					return fmt.Errorf("error processing rules: %w", err)
				}

				return nil
			},
		},
		{
			Name:  "support",
			Usage: "Show supported criteria matrix",
			Action: func(c *cli.Context) error {
				converter := convert.NewRuleConverter(convert.ConversionConfig{})

				converter.ShowRules()
				return nil
			},
		},
	}

	app := &cli.App{
		Name:        "nvrules2kw",
		Usage:       "Convert NeuVector Admission Control Rules to Kubewarden Policies",
		UsageText:   "nvrules2kw [global options] command [command options] [arguments...]",
		Description: appDescription,
		Commands:    commands,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
