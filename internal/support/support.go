package support

import (
	"fmt"
	"os"

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

	_, err = os.Stdout.WriteString(rendered)
	return err
}
