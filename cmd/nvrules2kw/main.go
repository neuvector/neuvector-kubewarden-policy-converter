/*
Copyright 2025.

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

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internals/convert"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "nvrules2kw",
		Usage: "Convert NeuVector Admission Control Rules to Kubewarden Policies",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "rulefile",
				Usage: "Path to the NeuVector rules JSON file (output from the /v1/admission/rules API)",
			},
			&cli.StringFlag{
				Name:  "policyserver",
				Value: "default",
				Usage: "Bound to Policy Server",
			},
			&cli.BoolFlag{
				Name:  "backgroundaudit",
				Usage: "Whether the policy is used in audit checks (default: false)",
			},
			&cli.StringFlag{
				Name:  "output",
				Usage: "Output file for the generated policy (default: stdout)",
			},
		},
		Action: func(c *cli.Context) error {
			ruleFile := c.String("rulefile")
			policyServer := c.String("policyserver")
			backgroundAudit := c.Bool("backgroundaudit")
			outputFile := c.String("output")

			// Fallback help if no rulefile and no stdin
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
					// Data is piped into stdin
					input = os.Stdin
				} else {
					cli.ShowAppHelpAndExit(c, 1)
				}
			}

			if err := convert.ProcessRules(input, convert.ConversionConfig{OutputFile: outputFile, PolicyServer: policyServer, BackgroundAudit: backgroundAudit}); err != nil {
				return fmt.Errorf("error processing rules: %w", err)
			}

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
