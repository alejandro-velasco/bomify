package cmd

import (
	"strings"
	"testing"
)

func TestFormatTypeSet(t *testing.T) {
	for name, test := range map[string]struct {
		value string
		want  formatType
	}{
		"json":       {value: "json", want: formatTypeJSON},
		"text":       {value: "text", want: formatTypeText},
		"upper case": {value: "JSON", want: formatTypeJSON},
	} {
		t.Run(name, func(t *testing.T) {
			format := defaultFormatType

			if err := format.Set(test.value); err != nil {
				t.Fatalf("Set(%q): %v", test.value, err)
			}

			if format != test.want {
				t.Errorf("Set(%q) = %q, want %q", test.value, format, test.want)
			}
			if format.String() != string(test.want) {
				t.Errorf("String() = %q, want %q", format.String(), test.want)
			}
		})
	}
}

func TestFormatTypeSetRefusesUnknownFormats(t *testing.T) {
	for _, value := range []string{"yaml", "", "jsonl"} {
		t.Run(value, func(t *testing.T) {
			format := defaultFormatType

			err := format.Set(value)

			if err == nil {
				t.Fatalf("Set(%q) succeeded, want an error", value)
			}
			for _, accepted := range []formatType{formatTypeJSON, formatTypeText} {
				if !strings.Contains(err.Error(), string(accepted)) {
					t.Errorf("Set(%q) error = %v, want it to name %q", value, err, accepted)
				}
			}
			if format != defaultFormatType {
				t.Errorf("Set(%q) changed the format to %q", value, format)
			}
		})
	}
}

func TestDeployGenerateFormatFlag(t *testing.T) {
	for name, test := range map[string]struct {
		args    []string
		want    formatType
		wantErr string
	}{
		"default":    {args: nil, want: formatTypeText},
		"long":       {args: []string{"--format", "json"}, want: formatTypeJSON},
		"shorthand":  {args: []string{"-F", "json"}, want: formatTypeJSON},
		"unknown":    {args: []string{"--format", "yaml"}, wantErr: `invalid argument "yaml" for "-F, --format" flag`},
		"no value":   {args: []string{"--format"}, wantErr: "flag needs an argument"},
		"upper case": {args: []string{"--format", "TEXT"}, want: formatTypeText},
	} {
		t.Run(name, func(t *testing.T) {
			root, err := NewRootCmd()
			if err != nil {
				t.Fatalf("NewRootCmd() error = %v", err)
			}
			generate, _, err := root.Find([]string{"deploy", "generate"})
			if err != nil {
				t.Fatalf("find deploy generate: %v", err)
			}

			err = generate.ParseFlags(test.args)

			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Errorf("parse %q: error = %v, want it to contain %q", test.args, err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse %q: %v", test.args, err)
			}
			flag := generate.Flags().Lookup("format")
			if got := formatType(flag.Value.String()); got != test.want {
				t.Errorf("parse %q: --format = %q, want %q", test.args, got, test.want)
			}
		})
	}
}
