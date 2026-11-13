//go:build !linux && !windows

package runtime

func niceOf(int) int { return 0 }
