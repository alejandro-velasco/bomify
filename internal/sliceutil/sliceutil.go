// Package sliceutil holds small slice helpers shared across bomify.
package sliceutil

// Deref returns the slice p points to, or nil if p is nil: the lists in
// cyclonedx-go's types are pointers to slices, nil when a document has
// none, and a nil slice ranges and appends like an empty one.
func Deref[T any](p *[]T) []T {
	if p == nil {
		return nil
	}
	return *p
}
