package main

import (
	_ "bufio"
	"os/exec"
	"time"
)

// Perform a read on our netlink socket
func canaryRead() {
	for {
		exec.Command("/bin/cat", "/proc/net/netlink").Run()
		time.Sleep(time.Minute * 2)
	}
}
