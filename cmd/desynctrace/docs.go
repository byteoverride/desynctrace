package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var docDir string

var docsCmd = &cobra.Command{
	Use:   "docs",
	Short: "Generate documentation (man pages, markdown)",
	Run: func(cmd *cobra.Command, args []string) {
		if err := os.MkdirAll(docDir, 0755); err != nil {
			fmt.Printf("Error creating directory: %v\n", err)
			return
		}

		fmt.Printf("Generating documentation in %s...\n", docDir)

		// Generate Markdown docs
		if err := doc.GenMarkdownTree(rootCmd, docDir); err != nil {
			fmt.Printf("Error generating markdown: %v\n", err)
		} else {
			fmt.Println("[+] Markdown documentation generated")
		}

		// Generate Man pages
		header := &doc.GenManHeader{
			Title:   "DESYNCTRACE",
			Section: "1",
		}
		if err := doc.GenManTree(rootCmd, header, docDir); err != nil {
			fmt.Printf("Error generating man pages: %v\n", err)
		} else {
			fmt.Println("[+] Man pages generated")
		}
	},
}

func init() {
	rootCmd.AddCommand(docsCmd)
	docsCmd.Flags().StringVarP(&docDir, "dir", "d", "docs/", "Directory to save documentation")
}
