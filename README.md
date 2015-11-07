# go-audit

## About

go-audit is an alternative to the auditd daemon that ships with many distros.
After having created an [auditd audisp](https://people.redhat.com/sgrubb/audit/) plugin to convert audit logs to json, 
I became interested in creating a replacement for the existing daemon.

##### Goals
* Safe : Written in a modern language that is type safe and performant
* Fast : Never ever ever ever block if we can avoid it
* Outputs json : Yay
* Pluggable pipelines : Reports to syslog by default, but easily extended via channels
* Connects to the linux kernel via netlink (info [here](https://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/tree/kernel/audit.c?id=refs/tags/v3.14.56) and [here](https://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/tree/include/uapi/linux/audit.h?h=linux-3.14.y))

##### Installation

1. Install [golang](https://golang.org/doc/install)

2.

```
  Build the binary
  git clone (this repo)
  cd go-audit
  go build
```

3. Copy binary `go-audit` to wherever you'd like

##### Example Config 

_Note: _ Configuration must be in /etc/audit/go-audit.yaml or cwd

```
canary:
  true
canary_host:
  127.0.0.1
canary_port:
  1234

rules:
  - -a exit,always -F arch=b64 -S execve
  - -a exit,always -F arch=b32 -S execve
```

## Thanks!
To Hardik Juneja, Arun Sori, Aalekh Nigam Aalekhn for the inspiration via https://github.com/mozilla/audit-go
