// Package parallel runs the same work over a slice of items concurrently,
// with a limit, stopping at the first error, as bomify's transfers do:
// layers, file parts, and reports.
package parallel

import (
	"context"

	"golang.org/x/sync/errgroup"
)

// Map runs fn on each of items, up to limit at once (no limit if it's
// zero or less), and returns its results in items' order, whichever
// finishes first. The first error cancels the others, through fn's
// context, and is returned.
func Map[T, R any](ctx context.Context, limit int, items []T, fn func(ctx context.Context, index int, item T) (R, error)) ([]R, error) {
	results := make([]R, len(items))
	err := ForEach(ctx, limit, items, func(ctx context.Context, index int, item T) error {
		result, err := fn(ctx, index, item)
		if err != nil {
			return err
		}
		results[index] = result
		return nil
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

// ForEach is Map without results.
func ForEach[T any](ctx context.Context, limit int, items []T, fn func(ctx context.Context, index int, item T) error) error {
	group, groupCtx := errgroup.WithContext(ctx)
	if limit > 0 {
		group.SetLimit(limit)
	}
	for index, item := range items {
		group.Go(func() error {
			return fn(groupCtx, index, item)
		})
	}
	return group.Wait()
}
