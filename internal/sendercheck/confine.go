package sendercheck

import (
	"errors"
	"log"
	"os/exec"
	"sync/atomic"
	"syscall"
)

type confinement struct {
	name string
	attr *syscall.SysProcAttr
}

// chosen is the strongest confinement that has started a child. It only weakens.
var chosen atomic.Int32

// start builds and starts a child under the strongest confinement this
// environment allows. setup wires the new command's pipes; an exec.Cmd starts
// only once, so each try builds its own.
func start(build func() *exec.Cmd, setup func(*exec.Cmd) error) (*exec.Cmd, error) {
	cs := confinements()
	for i := int(chosen.Load()); i < len(cs); i++ {
		cmd := build()
		cmd.SysProcAttr = cs[i].attr
		if err := setup(cmd); err != nil {
			return nil, err
		}
		err := cmd.Start()
		if err == nil {
			changed := chosen.Swap(int32(i)) != int32(i)
			if first := !logged.Swap(true); first || changed {
				log.Printf("sendercheck: child confinement: %s", cs[i].name)
			}
			return cmd, nil
		}
		if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.EACCES) {
			return nil, err
		}
	}
	return nil, errors.New("sendercheck: the child couldn't start")
}

var logged atomic.Bool
