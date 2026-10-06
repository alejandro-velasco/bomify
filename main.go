package main

import (
	"os"
	"strings"

	"github.com/alejandro-velasco/bomify/cmd"
	"github.com/alejandro-velasco/bomify/internal/logging"
)

func main() {
	rootCmd, err := cmd.NewRootCmd()
	if err != nil {
		fail(err)
	}

	if err := rootCmd.Execute(); err != nil {
		fail(err)
	}
}

// fail logs err as an error line, formatted like bomify's other log
// output, and exits 1. Lines after the first, as an errors.Join error
// has, are indented under it.
func fail(err error) {
	message := strings.ReplaceAll(err.Error(), "\n", "\n    ")
	logging.New(false).Error(message)
	os.Exit(1)
}
