package sendercheck

import (
	"os"
	"syscall"
)

// confinements are tried in order, strongest first. A container may refuse new
// namespaces, and only root can change user, so each step drops what the
// environment won't allow.
func confinements() []confinement {
	var nobody *syscall.Credential
	if os.Getuid() == 0 {
		// The attested keys are root's files; nobody can't read them.
		nobody = &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}
	}
	return []confinement{
		{"no network, nobody", &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC, Credential: nobody, Pdeathsig: syscall.SIGKILL}},
		{"nobody", &syscall.SysProcAttr{Credential: nobody, Pdeathsig: syscall.SIGKILL}},
		{"none", &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}},
	}
}
