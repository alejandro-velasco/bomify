package cmd

import (
	"fmt"
	"strings"
)

// formatType is a --format value: how a command prints its result. It
// implements pflag.Value, so the flag refuses any other.
type formatType string

const (
	formatTypeJSON formatType = "json"
	formatTypeText formatType = "text"
)

// defaultFormatType is --format's default.
const defaultFormatType = formatTypeText

func (f *formatType) String() string {
	return string(*f)
}

// Set sets f to val, in any case, refusing a format it isn't.
func (f *formatType) Set(val string) error {
	format := formatType(strings.ToLower(val))
	if format != formatTypeJSON && format != formatTypeText {
		return fmt.Errorf("must be %s or %s", formatTypeJSON, formatTypeText)
	}
	*f = format
	return nil
}

// Type is the flag's value placeholder in help: "--format format".
func (f *formatType) Type() string {
	return "format"
}
