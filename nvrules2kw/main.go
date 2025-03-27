package main

import (
	"embed"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

//go:embed templates/*.yaml
var yamlFiles embed.FS

func main() {
	// Define the -f flag with a default value and usage description
	filePath := flag.String("f", "", "Path to the rules file (e.g., ./rules/nvrules1.json)")
	flag.Parse()

	var input io.Reader
	if *filePath != "" {
		file, err := os.Open(*filePath)
		if err != nil {
			log.Fatalf("Error opening file: %v", err)
		}
		defer file.Close()
		input = file
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			// Data is being piped in
			input = os.Stdin
		} else {
			fmt.Println("Usage: nv2kwctl -f <path-to-rules-file> or provide input via stdin (e.g., curl ... | nv2kwctl)")
			flag.PrintDefaults()
			return
		}
	}

	// Process the specified rules file
	if err := ProcessRules(input); err != nil {
		log.Fatalf("Error processing rules: %v", err)
	}
}
