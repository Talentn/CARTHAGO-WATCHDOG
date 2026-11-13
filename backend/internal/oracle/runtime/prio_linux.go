package runtime

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

func lowPriority(cmd *exec.Cmd) {
	// The child dies with the gateway, however the gateway goes.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

func afterStart(cmd *exec.Cmd) {
	// Threads the server creates later inherit the value set here.
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, cmd.Process.Pid, niceness)
}

// afterReady covers threads the server may have created before afterStart ran: on Linux
// a nice value belongs to a thread, not to the process.
func afterReady(cmd *exec.Cmd) {
	tasks, err := os.ReadDir("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/task")
	if err != nil {
		return
	}
	for _, t := range tasks {
		if tid, err := strconv.Atoi(t.Name()); err == nil {
			_ = syscall.Setpriority(syscall.PRIO_PROCESS, tid, niceness)
		}
	}
}
