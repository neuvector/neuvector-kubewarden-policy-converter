package support

import (
	"fmt"

	"github.com/charmbracelet/glamour"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/docs"
)

func RenderSupport() error {
	renderer, err := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithInlineTableLinks(true),
	)
	if err != nil {
		return fmt.Errorf("failed to create renderer: %w", err)
	}

	rendered, err := renderer.Render(string(docs.Support))
	if err != nil {
		return fmt.Errorf("failed to render markdown: %w", err)
	}

	//nolint:forbidigo // Use rendered to print the support matrix to the console
	fmt.Print(rendered)
	return nil
}
