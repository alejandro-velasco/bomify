package parallel

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

func TestMapKeepsOrder(t *testing.T) {
	items := []int{5, 1, 4, 2, 3}

	// Later items finish first, so completion order is the reverse.
	results, err := Map(context.Background(), 0, items, func(_ context.Context, index int, item int) (int, error) {
		time.Sleep(time.Duration(len(items)-index) * time.Millisecond)
		return item * 10, nil
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if want := []int{50, 10, 40, 20, 30}; !slices.Equal(results, want) {
		t.Errorf("Map = %v, want %v", results, want)
	}
}

func TestForEachRespectsLimit(t *testing.T) {
	var running, peak atomic.Int32
	items := make([]int, 20)

	err := ForEach(context.Background(), 3, items, func(_ context.Context, _ int, _ int) error {
		now := running.Add(1)
		for {
			highest := peak.Load()
			if now <= highest || peak.CompareAndSwap(highest, now) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		running.Add(-1)
		return nil
	})
	if err != nil {
		t.Fatalf("ForEach: %v", err)
	}
	if got := peak.Load(); got > 3 {
		t.Errorf("%d ran at once, want at most 3", got)
	}
}

func TestForEachStopsAtFirstError(t *testing.T) {
	failure := errors.New("item 0 failed")
	var canceled atomic.Int32
	items := make([]int, 5)

	err := ForEach(context.Background(), 0, items, func(ctx context.Context, index int, _ int) error {
		if index == 0 {
			return failure
		}
		select {
		case <-ctx.Done():
			canceled.Add(1)
			return ctx.Err()
		case <-time.After(5 * time.Second):
			return nil
		}
	})
	if !errors.Is(err, failure) {
		t.Errorf("ForEach = %v, want the first error", err)
	}
	if got := canceled.Load(); got != int32(len(items)-1) {
		t.Errorf("%d of the others saw cancellation, want %d", got, len(items)-1)
	}
}

func TestMapReturnsNoResultsOnError(t *testing.T) {
	results, err := Map(context.Background(), 2, []int{1, 2}, func(_ context.Context, _ int, item int) (int, error) {
		if item == 2 {
			return 0, errors.New("failed")
		}
		return item, nil
	})
	if err == nil || results != nil {
		t.Errorf("Map = %v, %v; want no results and the error", results, err)
	}
}
