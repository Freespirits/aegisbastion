//go:build !windows

package evs

import (
	"os/exec"
	"syscall"
)

// setSandboxProcAttrs isolates the child into its own process group so
// context cancellation kills the whole tree (doc 04 §10.3: EVS tears down
// sandboxes immediately on kill).
func setSandboxProcAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}
