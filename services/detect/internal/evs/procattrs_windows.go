//go:build windows

package evs

import "os/exec"

// setSandboxProcAttrs is a no-op on Windows: CommandContext cancellation
// already kills the direct child; scanner/PoC children of the sandbox are
// not spawned on this platform at MVP.
func setSandboxProcAttrs(cmd *exec.Cmd) {}
