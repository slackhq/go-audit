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
# It is recommended you do not set any of these values unless you really need to
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
  
  # Maximum out of orderness before a missed sequence is presumed dropped, default 500
  max_out_of_order: 500

# Configure where to output logs to
output:
  # Currently only syslog is supported and it is the default value
  type: syslog
  syslog:
    # Configure the type of socket this should be, default is unixgram
    # This maps to `network` in golangs net.Dial: https://golang.org/pkg/net/#Dial
    network: unixgram
    
    # Set the remote address to connect to, this can be a path or an ip address
    # This maps to `address` in golangs net.Dial: https://golang.org/pkg/net/#Dial
    address: /dev/log
    
    # Sets the facility and severity for all events. See the table below for help
    # The default is 132 which maps to local0 | warn
    priority: 129 # local0 | emerg
    
    # Typically the name of the program generating the message. The PID is of the process is appended for you: [1233]
    # Default value is "go-audit"
    tag: "audit-thing"

rules:
  # Watch all 64 bit program executions
  - -a exit,always -F arch=b64 -S execve
  # Watch all 32 bit program executions
  - -a exit,always -F arch=b32 -S execve
```

##### Running as a service
 
Check the `contrib` folder, it contains examples for how to run `go-audit` as a proper service on your machine.

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

#### I don't like math and want you to tell me the syslog priority to use

Use the default, or consult this handy table.

Wikipedia has a pretty good [page](https://en.wikipedia.org/wiki/Syslog) on this

|                   | emerg (0)| alert (1) | crit (2)  | err (3) | warn (4) | notice (5) | info (6)  | debug (7) |
|-------------------|----------|-----------|-----------|---------|----------|------------|-----------|-----------|
| **kernel (0)**    | 0        | 1         | 2         | 3       | 4        | 5          | 6         | 7         |
| **user (1)**      | 8        | 9         | 10        | 11      | 12       | 13         | 14        | 15        |
| **mail (2)**      | 16       | 17        | 18        | 19      | 20       | 21         | 22        | 23        |
| **daemon (3)**    | 24       | 25        | 26        | 27      | 28       | 29         | 30        | 31        |
| **auth (4)**      | 32       | 33        | 34        | 35      | 36       | 37         | 38        | 39        |
| **syslog (5)**    | 40       | 41        | 42        | 43      | 44       | 45         | 46        | 47        |
| **lpr (6)**       | 48       | 49        | 50        | 51      | 52       | 53         | 54        | 55        |
| **news (7)**      | 56       | 57        | 58        | 59      | 60       | 61         | 62        | 63        |
| **uucp (8)**      | 64       | 65        | 66        | 67      | 68       | 69         | 70        | 71        |
| **clock (9)**     | 72       | 73        | 74        | 75      | 76       | 77         | 78        | 79        |
| **authpriv (10)** | 80       | 81        | 82        | 83      | 84       | 85         | 86        | 87        |
| **ftp (11)**      | 88       | 89        | 90        | 91      | 92       | 93         | 94        | 95        |
| **ntp (12)**      | 96       | 97        | 98        | 99      | 100      | 101        | 102       | 103       |
| **logaudit (13)** | 104      | 105       | 106       | 107     | 108      | 109        | 110       | 111       |
| **logalert (14)** | 112      | 113       | 114       | 115     | 116      | 117        | 118       | 119       |
| **cron (15)**     | 120      | 121       | 122       | 123     | 124      | 125        | 126       | 127       |
| **local0 (16)**   | 128      | 129       | 130       | 131     | 132      | 133        | 134       | 135       |
| **local1 (17)**   | 136      | 137       | 138       | 139     | 140      | 141        | 142       | 143       |
| **local2 (18)**   | 144      | 145       | 146       | 147     | 148      | 149        | 150       | 151       |
| **local3 (19)**   | 152      | 153       | 154       | 155     | 156      | 157        | 158       | 159       |
| **local4 (20)**   | 160      | 161       | 162       | 163     | 164      | 165        | 166       | 167       |
| **local5 (21)**   | 168      | 169       | 170       | 171     | 172      | 173        | 174       | 175       |
| **local6 (22)**   | 176      | 177       | 178       | 179     | 180      | 181        | 182       | 183       |
| **local7 (23)**   | 184      | 185       | 186       | 187     | 188      | 189        | 190       | 191       |

## Thanks!

To Hardik Juneja, Arun Sori, Aalekh Nigam Aalekhn for the inspiration via https://github.com/mozilla/audit-go
