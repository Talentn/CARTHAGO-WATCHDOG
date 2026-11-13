//go:build !linux && !windows

package runtime

import (
	"os/exec"
	"syscall"
)

func lowPriority(*exec.Cmd) {}

func afterStart(cmd *exec.Cmd) {
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, cmd.Process.Pid, 10)
}
