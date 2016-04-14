# go-audit

## About

go-audit is an alternative to the auditd daemon that ships with many distros.
After having created an [auditd audisp](https://people.redhat.com/sgrubb/audit/) plugin to convert audit logs to json, 
I became interested in creating a replacement for the existing daemon.

##### Goals

* Safe : Written in a modern language that is type safe and performant
* Fast : Never ever ever ever block if we can avoid it
* Outputs json : Yay
* Pluggable pipelines : Reports to syslog by default, but easily extended
* Connects to the linux kernel via netlink (info [here](https://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/tree/kernel/audit.c?id=refs/tags/v3.14.56) and [here](https://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/tree/include/uapi/linux/audit.h?h=linux-3.14.y))

## Usage

##### Installation

1. Install [golang](https://golang.org/doc/install)

2. Build the binary
  ```
  git clone (this repo)
  cd go-audit
  go build
  ```
3. Copy binary `go-audit` to wherever you'd like

##### Example Config 

```
# Reads /proc/net/netlink every 5 seconds
# you should set a file watch rule to pick the file access `-w /proc/net/netlink -p war -k netlink-file`
canary: true

# Configure socket buffers, leave unset to use the system defaults
# Values will be doubled by the kernel 
socket_buffer:
    # Default is net.core.rmem_default (/proc/sys/net/core/rmem_default)
    # Maximum max is net.core.rmem_max (/proc/sys/net/core/rmem_max)
    receive: 16384

# Configure message sequence tracking
message_tracking:
  # Track messages and identify if we missed any, default true
  enabled: true

  # Log out of orderness, these messages typically signify an overloading system, default false
  log_out_of_order: false

rules:
  # Watch all 64 bit program executions
  - -a exit,always -F arch=b64 -S execve
  # Watch all 32 bit program executions
  - -a exit,always -F arch=b32 -S execve
```


## FAQ

#### I am seeing `Error during message receive: no buffer space available` in the logs

This is because `go-audit` is not receiving data as quickly as your system is generating it. You can increase
the receive buffer system wide and maybe it will help. Best to try and reduce the amount of data `go-audit` has
to handle.

If reducing audit velocity is not an option you can try increasing `socket_buffer.receive` in your config.
See [Example Config](#example-config) for more information

```
socket_buffer:
    receive: <some number bigger than (the current value * 2)>
```

#### Sometime files don't have a `name`, only `inode`, what gives?

The kernel doesn't always know the filename for file access. Figuring out the filename from an inode is expensive and
error prone.

You can map back to a filename, possibly not *the* filename, that triggured the audit line though.

```
sudo debugfs -R "ncheck <inode to map>" /dev/<your block device here>
```

## Thanks!

To Hardik Juneja, Arun Sori, Aalekh Nigam Aalekhn for the inspiration via https://github.com/mozilla/audit-go
