package runtime

import "syscall"

// niceOf returns a process's nice value. The raw system call reports 20 minus it.
func niceOf(pid int) int {
	v, err := syscall.Getpriority(syscall.PRIO_PROCESS, pid)
	if err != nil {
		return -100
	}
	return 20 - v
}
