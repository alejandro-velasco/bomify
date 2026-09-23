// Command fakeplugin is a synthetic bomify-plugin-* binary used only by
// cmd's tests, to exercise "bomify sbom generate"'s passthrough without
// depending on a real plugin. It echoes its own args to stdout and, if
// any arg is exactly "--fail", writes to stderr and exits non-zero
// instead — letting tests assert on both the success and failure paths.
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	fmt.Fprintln(os.Stdout, strings.Join(os.Args[1:], " "))

	for _, arg := range os.Args[1:] {
		if arg == "--fail" {
			fmt.Fprintln(os.Stderr, "simulated failure")
			os.Exit(7)
		}
	}
}
