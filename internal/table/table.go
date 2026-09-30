// Package table prints the column-aligned listings bomify's commands
// share ("bomify packages", "bomify trust list", a failed gate's
// findings, ...), so they all look alike.
package table

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Write prints header and then rows to w, each cell left-aligned in its
// column, columns three spaces apart.
func Write(w io.Writer, header []string, rows [][]string) error {
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	fmt.Fprintln(tw, strings.Join(header, "\t"))
	for _, row := range rows {
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	return tw.Flush()
}

// RightAlign left-pads column col of header and every row to one common
// width, so Write shows it right-aligned — the conventional way to show a
// column of numbers. (tabwriter itself aligns every column the same way.)
func RightAlign(col int, header []string, rows [][]string) {
	width := len(header[col])
	for _, row := range rows {
		width = max(width, len(row[col]))
	}

	header[col] = fmt.Sprintf("%*s", width, header[col])
	for _, row := range rows {
		row[col] = fmt.Sprintf("%*s", width, row[col])
	}
}
