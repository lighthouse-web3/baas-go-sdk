package utils

import "time"

// IntPtr returns a pointer to an int value.
func IntPtr(v int) *int { return &v }

// Int64Ptr returns a pointer to an int64 value.
func Int64Ptr(v int64) *int64 { return &v }

// UnixMilliPtr returns a pointer to Unix millisecond timestamp.
func UnixMilliPtr(t time.Time) *int64 {
	v := t.UnixMilli()
	return &v
}
