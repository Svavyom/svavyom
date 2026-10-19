package ctl

import (
	"net"
	"time"
)

func dialUnix(path string) error {
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return err
	}
	return c.Close()
}
