package runtime

import "golang.org/x/sys/windows"

// niceOf maps a process's priority class onto the nice value the other systems use, so
// one test covers both: below normal is the runtime's niceness, anything else is 0.
func niceOf(pid int) int {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return -100
	}
	defer windows.CloseHandle(h)
	class, err := windows.GetPriorityClass(h)
	if err != nil {
		return -100
	}
	if class == windows.BELOW_NORMAL_PRIORITY_CLASS {
		return niceness
	}
	return 0
}
