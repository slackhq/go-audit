# go-audit
A replacement for linux auditd, written in go.

### About

go-audit is a replacement for the auditd daemon that ships with many distros.
After having created an [auditd audisp](https://people.redhat.com/sgrubb/audit/) plugin to convert audit logs to json, 
I became interested in creating a replacement for the existing daemon.

#### Goals
* Safe : Written in a modern language that is type safe and performant
* Fast : Never ever ever ever block if we can avoid it
* Outputs json : Yay
* Pluggable pipelines : Reports to syslog by default, but easily extended via channels

Connects to the linux kernel via netlink (info [here](https://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/tree/kernel/audit.c?id=refs/tags/v3.14.56) and [here](https://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/tree/include/uapi/linux/audit.h?h=linux-3.14.y)

# Thanks!
To Hardik Juneja, Arun Sori, Aalekh Nigam Aalekhn for the inspiration via https://github.com/mozilla/audit-go
