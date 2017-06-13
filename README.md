# go-audit

[![License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](http://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/travis/slackhq/go-audit.svg?style=flat-square)](https://travis-ci.org/slackhq/go-audit)
[![codecov](https://codecov.io/gh/slackhq/go-audit/branch/master/graph/badge.svg)](https://codecov.io/gh/slackhq/go-audit)

## About

go-audit is an alternative to the auditd daemon that ships with many distros.
After having created an [auditd audisp](https://people.redhat.com/sgrubb/audit/) plugin to convert audit logs to json, 
I became interested in creating a replacement for the existing daemon.

##### Goals

* Safe : Written in a modern language that is type safe and performant
* Fast : Never ever ever ever block if we can avoid it
* Outputs json : Yay
* Pluggable pipelines : Can write to syslog, local file, or stdout. Additional outputs are easily written. 
* Connects to the linux kernel via netlink (info [here](https://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/tree/kernel/audit.c?id=refs/tags/v3.14.56) and [here](https://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/tree/include/uapi/linux/audit.h?h=linux-3.14.y))

## Usage

##### Installation

1. Install [golang](https://golang.org/doc/install), version 1.7 or greater is required
2. Install [`govendor`](https://github.com/kardianos/govendor) if you haven't already

    ```go get -u github.com/kardianos/govendor```
    
2. Clone the repo

    ```
    git clone (this repo)
    cd go-audit
    ```
    
2. Build the binary

    ```
    make
    ```

3. Copy the binary `go-audit` to wherever you'd like

##### Testing

- `make test` - run the unit test suite
- `make test-cov-html` - run the unit tests and open up the code coverage results
- `make bench` - run the benchmark test suite
- `make bench-cpu` - run the benchmark test suite with cpu profiling
- `make bench-cpulong` - run the benchmark test suite with cpu profiling and try to get some gc collection

##### Running as a service
 
Check the [contrib](contrib) folder, it contains examples for how to run `go-audit` as a proper service on your machine.

##### Example Config 

See [go-audit.yaml.example](go-audit.yaml.example)

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

#### I am seeing duplicate entries in syslog!

This is likely because you are running `journald` which is also reading audit events. To disable it you need to disable the functionality in `journald`.

```sh
sudo systemctl mask systemd-journald-audit.socket
```

## Thanks!

To Hardik Juneja, Arun Sori, Aalekh Nigam Aalekhn for the inspiration via https://github.com/mozilla/audit-go
