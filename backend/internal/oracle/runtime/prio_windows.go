package runtime

import (
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func lowPriority(cmd *exec.Cmd) {
	// Below-normal priority from the first instruction, and no console window.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true,
		CreationFlags: windows.BELOW_NORMAL_PRIORITY_CLASS | windows.CREATE_NO_WINDOW}
}

// afterStart puts the child in a job that is closed, and the child with it, when the
// gateway exits: Windows does not end child processes with their parent.
func afterStart(cmd *exec.Cmd) {
	// The priority class again, by name: the creation flag is the one that counts from
	// the first instruction, this covers a system that did not apply it.
	if p, err := windows.OpenProcess(windows.PROCESS_SET_INFORMATION, false, uint32(cmd.Process.Pid)); err == nil {
		_ = windows.SetPriorityClass(p, windows.BELOW_NORMAL_PRIORITY_CLASS)
		windows.CloseHandle(p)
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		windows.CloseHandle(job)
		return
	}
	defer windows.CloseHandle(h)
	// The job handle is deliberately kept open for the life of the gateway process.
	_ = windows.AssignProcessToJobObject(job, h)
}

func afterReady(*exec.Cmd) {}
