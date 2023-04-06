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

func TestContainerID(t *testing.T) {
	assert.Equal(t,
		"5c69ff1a4edf85228df5153f36cacbdee440ad6fd585704e77f50f54d3e58249",
		containerID("/docker/5c69ff1a4edf85228df5153f36cacbdee440ad6fd585704e77f50f54d3e58249"),
	)
	assert.Equal(t,
		"2ce19d7466dbb3eb7b7493be01b6d3353c990e6722258e94fac8016baeefd6c8",
		containerID("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podd12649dc_490b_4e0c_b6fe_9e2fbf4a058c.slice/cri-containerd-2ce19d7466dbb3eb7b7493be01b6d3353c990e6722258e94fac8016baeefd6c8.scope"),
	)
	assert.Equal(t,
		"d84f26ddf627f6fde170d83478b4ae9d5baaaa645e484b755a46844f3da785c6",
		containerID("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podec04832a_309d_4044_9f92_7fac604a2384.slice/docker-d84f26ddf627f6fde170d83478b4ae9d5baaaa645e484b755a46844f3da785c6.scope"),
	)
}
