package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetPid(t *testing.T) {
	data := "arch=c0000000 syscall=59 success=yes exit=0 a0=1600000 a1=1600000 a2=1600000 a3=500 items=2 ppid=30296 pid=31475 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=4294967295 comm=\"date\" exe=\"/bin/date\" key=(null)"

	pid, ppid := getPid(data)
	assert.Equal(t, pid, 31475)
	assert.Equal(t, ppid, 30296)

	data = "pid=31475 foo=bar ppid=30296"

	pid, ppid = getPid(data)
	assert.Equal(t, pid, 31475)
	assert.Equal(t, ppid, 30296)

	data = "pid=31475 foo=bar"

	pid, ppid = getPid(data)
	assert.Equal(t, pid, 31475)
	assert.Equal(t, ppid, 0)
}
