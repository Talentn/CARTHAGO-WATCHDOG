//go:build !linux

package runtime

func niceOf(int) int { return 0 }
