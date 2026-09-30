package table

import (
	"bytes"
	"testing"
)

func TestWrite(t *testing.T) {
	var out bytes.Buffer
	err := Write(&out, []string{"NAME", "VALUE"}, [][]string{{"a", "1"}, {"longer", "2"}})
	if err != nil {
		t.Fatal(err)
	}

	want := "NAME     VALUE\n" +
		"a        1\n" +
		"longer   2\n"
	if out.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestRightAlign(t *testing.T) {
	header := []string{"NAME", "SIZE"}
	rows := [][]string{{"a", "1.5"}, {"b", "1024.0"}}
	RightAlign(1, header, rows)

	var out bytes.Buffer
	if err := Write(&out, header, rows); err != nil {
		t.Fatal(err)
	}

	want := "NAME     SIZE\n" +
		"a         1.5\n" +
		"b      1024.0\n"
	if out.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", out.String(), want)
	}
}
