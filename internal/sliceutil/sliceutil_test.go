package sliceutil

import "testing"

func TestDeref(t *testing.T) {
	if got := Deref[int](nil); got != nil {
		t.Errorf("Deref(nil) = %v, want nil", got)
	}
	s := []int{1, 2}
	if got := Deref(&s); len(got) != 2 || &got[0] != &s[0] {
		t.Errorf("Deref(&s) = %v, want s itself", got)
	}
}
