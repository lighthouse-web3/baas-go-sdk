package pool

import "sync"

// Batch splits a slice into fixed-size sub-slices.
func Batch[T any](items []T, size int) [][]T {
	var out [][]T
	for i := 0; i < len(items); i += size {
		end := i + size
		if end > len(items) {
			end = len(items)
		}
		out = append(out, items[i:end])
	}
	return out
}

// Parallel executes fn over items with at most concurrency goroutines.
func Parallel[T any](items []T, concurrency int, fn func(T) error) error {
	if len(items) == 0 {
		return nil
	}
	if concurrency <= 0 {
		concurrency = 1
	}
	if concurrency > len(items) {
		concurrency = len(items)
	}

	ch := make(chan T, len(items))
	for _, item := range items {
		ch <- item
	}
	close(ch)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range ch {
				mu.Lock()
				if firstErr != nil {
					mu.Unlock()
					return
				}
				mu.Unlock()

				if err := fn(item); err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					return
				}
			}
		}()
	}

	wg.Wait()
	return firstErr
}
