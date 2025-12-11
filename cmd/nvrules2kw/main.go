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
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/convert"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/support"

	"github.com/urfave/cli/v3"
)

const appDescription = `
nvrules2kw converts NeuVector Admission Control rules into Kubewarden ClusterAdmissionPolicy YAMLs.

Use "nvrules2kw <command> --help" for details on each command.
`

//nolint:funlen // The main function intentionally declares many arguments and flags for clarity and usability; it's acceptable to suppress the linter warning about function length here.
func main() {
	var commands = []*cli.Command{
		{
			Name:  "convert",
			Usage: "Convert NeuVector Admission Control rules into Kubewarden policies",
			UsageText: `convert [OPTIONS] [INPUT_FILE] - specifies the input file:
			  - JSON: rules.json exported from the NeuVector UI
			  - YAML: one or more NvAdmissionControlSecurityRule CRD objects`,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "policyserver",
					Value: "default",
					Usage: "Name of the PolicyServer to bind the generated policies to",
				},
				&cli.StringFlag{
					Name:  "vulreportnamespace",
					Value: "sbomscanner",
					Usage: "Namespace where the vulnerability report is stored",
				},
				&cli.StringFlag{
					Name:  "platform",
					Value: "amd64",
					Usage: "Architecture of the platform, must use values listed in the Go Language document for GOARCH (e.g.: amd64, arm64, s390x).",
				},
				&cli.BoolFlag{
					Name:  "backgroundaudit",
					Value: true,
					Usage: "Run the generated policies in audit (background) mode",
				},
				&cli.StringFlag{
					Name:  "output",
					Value: "policies.yaml",
					Usage: "Path to the output file (use '-' for stdout)",
				},
				&cli.StringFlag{
					Name:  "mode",
					Value: "protect",
					Usage: "Execution mode of the policies: 'protect' or 'monitor'",
				},
				&cli.BoolFlag{
					Name:  "show-summary",
					Usage: "Display a summary table of the conversion results",
				},
			},
			Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
				mode := cmd.String("mode")
				if mode != "protect" && mode != "monitor" {
					return ctx, fmt.Errorf("invalid mode: %s. Allowed values are \"protect\" or \"monitor\"", mode)
				}
				return ctx, nil
			},
			Action: func(_ context.Context, cmd *cli.Command) error {
				args := cmd.Args().Slice()
				if len(args) == 0 {
					return errors.New("input file is required")
				}

				ruleFile := args[len(args)-1]
				policyServer := cmd.String("policyserver")
				backgroundAudit := cmd.Bool("backgroundaudit")
				outputFile := cmd.String("output")
				mode := cmd.String("mode")
				showSummary := cmd.Bool("show-summary")
				vulReportNamespace := cmd.String("vulreportnamespace")
				platform := cmd.String("platform")

				converter := convert.NewRuleConverter(share.ConversionConfig{
					OutputFile:         outputFile,
					Mode:               mode,
					PolicyServer:       policyServer,
					BackgroundAudit:    backgroundAudit,
					ShowSummary:        showSummary,
					VulReportNamespace: vulReportNamespace,
					Platform:           platform,
				})

				if err := converter.Convert(ruleFile); err != nil {
					return fmt.Errorf("error processing rules: %w", err)
				}
				return nil
			},
		},
		{
			Name:  "support",
			Usage: "Show supported criteria matrix",
			Action: func(_ context.Context, _ *cli.Command) error {
				return support.RenderSupport()
			},
		},
		{
			Name:  "version",
			Usage: "Print version information",
			Action: func(_ context.Context, _ *cli.Command) error {
				//nolint: forbidigo // it's fine to print to stdout
				fmt.Printf("%s\n", internal.CurrentVersion().String())
				return nil
			},
		},
	}

	cmd := &cli.Command{
		Name:        "nvrules2kw",
		Usage:       "Convert NeuVector Admission Control Rules to Kubewarden Policies",
		UsageText:   "nvrules2kw [global options] command [command options] [arguments...]",
		Description: appDescription,
		Commands:    commands,
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
