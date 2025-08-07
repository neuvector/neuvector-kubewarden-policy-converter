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
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"

	"github.com/urfave/cli/v2"
)

const appDescription = `
nvrules2kw converts NeuVector Admission Control rules into Kubewarden ClusterAdmissionPolicy YAMLs.

Use "nvrules2kw <command> --help" for details on each command.
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

				converter := convert.NewRuleConverter(share.ConversionConfig{
					OutputFile:      outputFile,
					Mode:            mode,
					PolicyServer:    policyServer,
					BackgroundAudit: backgroundAudit,
				})

				if err := converter.Convert(input); err != nil {
					return fmt.Errorf("error processing rules: %w", err)
				}

				return nil
			},
		},
		{
			Name:  "support",
			Usage: "Show supported criteria matrix",
			Action: func(_ *cli.Context) error {
				converter := convert.NewRuleConverter(share.ConversionConfig{})

				return converter.ShowRules()
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
