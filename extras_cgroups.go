package main

import (
	"github.com/spf13/viper"
)

func init() {
	RegisterExtraParser(func(config *viper.Viper) (ExtraParser, error) {
		if config.GetBool("extras.cgroups.enabled") {
			l.Printf("cgroup parser enabled")
			return &CgroupParser{}, nil
		}
		return nil, nil
	})
}

type CgroupParser struct {
}

func (p *CgroupParser) Parse(am *AuditMessage) {
	switch am.Type {
	case 1300, 1302, 1309, 1326: // AUDIT_SYSCALL, AUDIT_PATH, AUDIT_EXECVE, AUDIT_SECCOMP
		pid, _ := getPid(am.Data)
		cgroup := p.getCgroupRootForPid(pid)
		if cgroup != "" {
			am.Extras = &AuditExtras{CgroupRoot: cgroup}
		}
	}
}

func (p *CgroupParser) getCgroupRootForPid(pid int) string {
	if pid == 0 {
		return ""
	}

	var v1PidPath string
	cgroups, err := taskControlGroups(pid, pid)
	if err != nil {
		return ""
	}

	for _, cgroup := range cgroups {
		if cgroup.ID == 0 {
			// v2 path
			return cgroup.Path
		} else if len(cgroup.Controllers) > 0 && cgroup.Controllers[0] == "pids" {
			// fall back to cgroup v1 pid path if we don't have cgroups v2
			v1PidPath = cgroup.Path
		}
	}

	return v1PidPath
}
