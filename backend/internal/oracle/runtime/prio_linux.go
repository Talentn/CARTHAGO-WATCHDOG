package runtime

import (
	"os/exec"
	"syscall"
)

// niceness is the scheduling priority the model runs at: below everything interactive.
const niceness = 10

func lowPriority(cmd *exec.Cmd) {
	// The child dies with the gateway, however the gateway goes.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

func afterStart(cmd *exec.Cmd) {
	// Threads the server creates later inherit the value set here.
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, cmd.Process.Pid, niceness)
}
