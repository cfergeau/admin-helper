//go:build darwin || linux
// +build darwin linux

package hosts

import (
	"fmt"
	"syscall"
)

func DropPrivileges() error {
	return dropPrivilegesFn()
}

var (
	dropPrivilegesFn = dropPrivileges
	sysSetgroups     = syscall.Setgroups
	sysSetgid        = syscall.Setgid
	sysSetuid        = syscall.Setuid
)

func needsPrivilegeDrop(targetUID, targetGID int, ok bool, euid, egid, uid int) bool {
	if !ok {
		return false
	}

	// Not running with elevated privileges.
	if euid == uid && euid != 0 {
		return false
	}

	if euid == targetUID && egid == targetGID {
		return false
	}

	return true
}

func applyPrivilegeDrop(targetUID, targetGID int) error {
	if err := sysSetgroups([]int{}); err != nil {
		return fmt.Errorf("failed to drop supplementary groups: %w", err)
	}

	if err := sysSetgid(targetGID); err != nil {
		return fmt.Errorf("failed to setgid(%d): %w", targetGID, err)
	}

	if err := sysSetuid(targetUID); err != nil {
		return fmt.Errorf("failed to setuid(%d): %w", targetUID, err)
	}

	if err := sysSetuid(0); err == nil {
		return fmt.Errorf("able to regain root after dropping privileges")
	}

	return nil
}

func dropPrivilegesWithIdentity(targetUID, targetGID int, ok bool, euid, egid, uid int) error {
	if !needsPrivilegeDrop(targetUID, targetGID, ok, euid, egid, uid) {
		return nil
	}
	fmt.Println("dropping privileges", targetUID, targetGID)

	return applyPrivilegeDrop(targetUID, targetGID)
}

func dropPrivileges() error {
	targetUID, targetGID, ok := privilegeDropTarget()
	return dropPrivilegesWithIdentity(targetUID, targetGID, ok, syscall.Geteuid(), syscall.Getegid(), syscall.Getuid())
}

func privilegeDropTarget() (uid, gid int, ok bool) {
	realUID := syscall.Getuid()
	realGID := syscall.Getgid()
	if realUID == 0 {
		return 0, 0, false
	}
	return realUID, realGID, true
}
