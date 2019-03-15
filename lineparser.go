package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// https://github.com/torvalds/linux/blob/master/include/uapi/linux/audit.h#L86

const (
	AUDIT_SYSCALL        = 1300 // Syscall event
	AUDIT_PATH           = 1302 // Filename path information
	AUDIT_IPC            = 1303 // IPC record
	AUDIT_SOCKETCALL     = 1304 // sys_socketcall arguments
	AUDIT_CONFIG_CHANGE  = 1305 // Audit system configuration change
	AUDIT_SOCKADDR       = 1306 // sockaddr copied as syscall arg
	AUDIT_CWD            = 1307 // Current working directory
	AUDIT_EXECVE         = 1309 // execve arguments
	AUDIT_IPC_SET_PERM   = 1311 // IPC new permissions record type
	AUDIT_MQ_OPEN        = 1312 // POSIX MQ open record type
	AUDIT_MQ_SENDRECV    = 1313 // POSIX MQ send/receive record type
	AUDIT_MQ_NOTIFY      = 1314 // POSIX MQ notify record type
	AUDIT_MQ_GETSETATTR  = 1315 // POSIX MQ get/set attribute record type
	AUDIT_KERNEL_OTHER   = 1316 // For use by 3rd party modules
	AUDIT_FD_PAIR        = 1317 // audit record for pipe/socketpair
	AUDIT_OBJ_PID        = 1318 // ptrace target
	AUDIT_TTY            = 1319 // Input on an administrative TTY
	AUDIT_EOE            = 1320 // End of multi-record event
	AUDIT_BPRM_FCAPS     = 1321 // Information about fcaps increasing perms
	AUDIT_CAPSET         = 1322 // Record showing argument to sys_capset
	AUDIT_MMAP           = 1323 // Record showing descriptor and flags in mmap
	AUDIT_NETFILTER_PKT  = 1324 // Packets traversing netfilter chains
	AUDIT_NETFILTER_CFG  = 1325 // Netfilter chain modifications
	AUDIT_SECCOMP        = 1326 // Secure Computing event
	AUDIT_PROCTITLE      = 1327 // Proctitle emit event
	AUDIT_FEATURE_CHANGE = 1328 // audit log listing feature changes
	AUDIT_REPLACE        = 1329 // Replace auditd if this packet unanswerd
	AUDIT_KERN_MODULE    = 1330 // Kernel Module events
	AUDIT_FANOTIFY       = 1331 // Fanotify access decision
)

var auditFriendlyNames = map[uint16]string{
	AUDIT_SYSCALL:        "syscall",
	AUDIT_PATH:           "path",
	AUDIT_IPC:            "ipc",
	AUDIT_SOCKETCALL:     "socketcall",
	AUDIT_CONFIG_CHANGE:  "config_change",
	AUDIT_SOCKADDR:       "sockaddr",
	AUDIT_CWD:            "cwd",
	AUDIT_EXECVE:         "execve",
	AUDIT_IPC_SET_PERM:   "ipc_set_perm",
	AUDIT_MQ_OPEN:        "mq_open",
	AUDIT_MQ_SENDRECV:    "mq_sendrecv",
	AUDIT_MQ_NOTIFY:      "mq_notify",
	AUDIT_MQ_GETSETATTR:  "mq_getsetattr",
	AUDIT_KERNEL_OTHER:   "kernel_other",
	AUDIT_FD_PAIR:        "fd_pair",
	AUDIT_OBJ_PID:        "obj_pid",
	AUDIT_TTY:            "tty",
	AUDIT_EOE:            "eoe",
	AUDIT_BPRM_FCAPS:     "bprm_fcaps",
	AUDIT_CAPSET:         "capset",
	AUDIT_MMAP:           "mmap",
	AUDIT_NETFILTER_PKT:  "netfilter_pkt",
	AUDIT_NETFILTER_CFG:  "netfilter_cfg",
	AUDIT_SECCOMP:        "seccomp",
	AUDIT_PROCTITLE:      "proctitle",
	AUDIT_FEATURE_CHANGE: "feature_change",
	AUDIT_REPLACE:        "replace",
	AUDIT_KERN_MODULE:    "kern_module",
	AUDIT_FANOTIFY:       "fanotify",
}

var syscallNumbers = map[uint16]string{
	0:   "read",
	1:   "write",
	2:   "open",
	3:   "close",
	4:   "stat",
	5:   "fstat",
	6:   "lstat",
	7:   "poll",
	8:   "lseek",
	9:   "mmap",
	10:  "mprotect",
	11:  "munmap",
	12:  "brk",
	13:  "rt_sigaction",
	14:  "rt_sigprocmask",
	15:  "rt_sigreturn",
	16:  "ioctl",
	17:  "pread64",
	18:  "pwrite64",
	19:  "readv",
	20:  "writev",
	21:  "access",
	22:  "pipe",
	23:  "select",
	24:  "sched_yield",
	25:  "mremap",
	26:  "msync",
	27:  "mincore",
	28:  "madvise",
	29:  "shmget",
	30:  "shmat",
	31:  "shmctl",
	32:  "dup",
	33:  "dup2",
	34:  "pause",
	35:  "nanosleep",
	36:  "getitimer",
	37:  "alarm",
	38:  "setitimer",
	39:  "getpid",
	40:  "sendfile",
	41:  "socket",
	42:  "connect",
	43:  "accept",
	44:  "sendto",
	45:  "recvfrom",
	46:  "sendmsg",
	47:  "recvmsg",
	48:  "shutdown",
	49:  "bind",
	50:  "listen",
	51:  "getsockname",
	52:  "getpeername",
	53:  "socketpair",
	54:  "setsockopt",
	55:  "getsockopt",
	56:  "clone",
	57:  "fork",
	58:  "vfork",
	59:  "execve",
	60:  "exit",
	61:  "wait4",
	62:  "kill",
	63:  "uname",
	64:  "semget",
	65:  "semop",
	66:  "semctl",
	67:  "shmdt",
	68:  "msgget",
	69:  "msgsnd",
	70:  "msgrcv",
	71:  "msgctl",
	72:  "fcntl",
	73:  "flock",
	74:  "fsync",
	75:  "fdatasync",
	76:  "truncate",
	77:  "ftruncate",
	78:  "getdents",
	79:  "getcwd",
	80:  "chdir",
	81:  "fchdir",
	82:  "rename",
	83:  "mkdir",
	84:  "rmdir",
	85:  "creat",
	86:  "link",
	87:  "unlink",
	88:  "symlink",
	89:  "readlink",
	90:  "chmod",
	91:  "fchmod",
	92:  "chown",
	93:  "fchown",
	94:  "lchown",
	95:  "umask",
	96:  "gettimeofday",
	97:  "getrlimit",
	98:  "getrusage",
	99:  "sysinfo",
	100: "times",
	101: "ptrace",
	102: "getuid",
	103: "syslog",
	104: "getgid",
	105: "setuid",
	106: "setgid",
	107: "geteuid",
	108: "getegid",
	109: "setpgid",
	110: "getppid",
	111: "getpgrp",
	112: "setsid",
	113: "setreuid",
	114: "setregid",
	115: "getgroups",
	116: "setgroups",
	117: "setresuid",
	118: "getresuid",
	119: "setresgid",
	120: "getresgid",
	121: "getpgid",
	122: "setfsuid",
	123: "setfsgid",
	124: "getsid",
	125: "capget",
	126: "capset",
	127: "rt_sigpending",
	128: "rt_sigtimedwait",
	129: "rt_sigqueueinfo",
	130: "rt_sigsuspend",
	131: "sigaltstack",
	132: "utime",
	133: "mknod",
	134: "uselib",
	135: "personality",
	136: "ustat",
	137: "statfs",
	138: "fstatfs",
	139: "sysfs",
	140: "getpriority",
	141: "setpriority",
	142: "sched_setparam",
	143: "sched_getparam",
	144: "sched_setscheduler",
	145: "sched_getscheduler",
	146: "sched_get_priority_max",
	147: "sched_get_priority_min",
	148: "sched_rr_get_interval",
	149: "mlock",
	150: "munlock",
	151: "mlockall",
	152: "munlockall",
	153: "vhangup",
	154: "modify_ldt",
	155: "pivot_root",
	156: "_sysctl",
	157: "prctl",
	158: "arch_prctl",
	159: "adjtimex",
	160: "setrlimit",
	161: "chroot",
	162: "sync",
	163: "acct",
	164: "settimeofday",
	165: "mount",
	166: "umount2",
	167: "swapon",
	168: "swapoff",
	169: "reboot",
	170: "sethostname",
	171: "setdomainname",
	172: "iopl",
	173: "ioperm",
	174: "create_module ",
	175: "init_module",
	176: "delete_module",
	177: "get_kernel_syms ",
	178: "query_module  ",
	179: "quotactl",
	180: "nfsservctl  ",
	181: "getpmsg ",
	182: "putpmsg ",
	183: "afs_syscall ",
	184: "tuxcall ",
	185: "security  ",
	186: "gettid",
	187: "readahead",
	188: "setxattr",
	189: "lsetxattr",
	190: "fsetxattr",
	191: "getxattr",
	192: "lgetxattr",
	193: "fgetxattr",
	194: "listxattr",
	195: "llistxattr",
	196: "flistxattr",
	197: "removexattr",
	198: "lremovexattr",
	199: "fremovexattr",
	200: "tkill",
	201: "time",
	202: "futex",
	203: "sched_setaffinity",
	204: "sched_getaffinity",
	205: "set_thread_area ",
	206: "io_setup",
	207: "io_destroy",
	208: "io_getevents",
	209: "io_submit",
	210: "io_cancel",
	211: "get_thread_area ",
	212: "lookup_dcookie",
	213: "epoll_create",
	214: "epoll_ctl_old ",
	215: "epoll_wait_old  ",
	216: "remap_file_pages",
	217: "getdents64",
	218: "set_tid_address",
	219: "restart_syscall",
	220: "semtimedop",
	221: "fadvise64",
	222: "timer_create",
	223: "timer_settime",
	224: "timer_gettime",
	225: "timer_getoverrun",
	226: "timer_delete",
	227: "clock_settime",
	228: "clock_gettime",
	229: "clock_getres",
	230: "clock_nanosleep",
	231: "exit_group",
	232: "epoll_wait",
	233: "epoll_ctl",
	234: "tgkill",
	235: "utimes",
	236: "vserver ",
	237: "mbind",
	238: "set_mempolicy",
	239: "get_mempolicy",
	240: "mq_open",
	241: "mq_unlink",
	242: "mq_timedsend",
	243: "mq_timedreceive",
	244: "mq_notify",
	245: "mq_getsetattr",
	246: "kexec_load",
	247: "waitid",
	248: "add_key",
	249: "request_key",
	250: "keyctl",
	251: "ioprio_set",
	252: "ioprio_get",
	253: "inotify_init",
	254: "inotify_add_watch",
	255: "inotify_rm_watch",
	256: "migrate_pages",
	257: "openat",
	258: "mkdirat",
	259: "mknodat",
	260: "fchownat",
	261: "futimesat",
	262: "newfstatat",
	263: "unlinkat",
	264: "renameat",
	265: "linkat",
	266: "symlinkat",
	267: "readlinkat",
	268: "fchmodat",
	269: "faccessat",
	270: "pselect6",
	271: "ppoll",
	272: "unshare",
	273: "set_robust_list",
	274: "get_robust_list",
	275: "splice",
	276: "tee",
	277: "sync_file_range",
	278: "vmsplice",
	279: "move_pages",
	280: "utimensat",
	281: "epoll_pwait",
	282: "signalfd",
	283: "timerfd_create",
	284: "eventfd",
	285: "fallocate",
	286: "timerfd_settime",
	287: "timerfd_gettime",
	288: "accept4",
	289: "signalfd4",
	290: "eventfd2",
	291: "epoll_create1",
	292: "dup3",
	293: "pipe2",
	294: "inotify_init1",
	295: "preadv",
	296: "pwritev",
	297: "rt_tgsigqueueinfo",
	298: "perf_event_open",
	299: "recvmmsg",
	300: "fanotify_init",
	301: "fanotify_mark",
	302: "prlimit64",
	303: "name_to_handle_at",
	304: "open_by_handle_at",
	305: "clock_adjtime",
	306: "syncfs",
	307: "sendmmsg",
	308: "setns",
	309: "getcpu",
	310: "process_vm_readv",
	311: "process_vm_writev",
	312: "kcmp",
	313: "finit_module",
}

var addressFamiles = map[uint16]string{
	0:  "unspecified",
	1:  "local",
	2:  "inet",
	3:  "ax25",
	4:  "ipx",
	5:  "appletalk",
	6:  "netrom",
	7:  "bridge",
	8:  "atmpvc",
	9:  "x25",
	10: "inet6",
	11: "rose",
	12: "decnet",
	13: "netbeui",
	14: "security",
	15: "key",
	16: "netlink",
	17: "packet",
	18: "ash",
	19: "econet",
	20: "atmsvc",
	21: "rds",
	22: "sna",
	23: "irda",
	24: "pppox",
	25: "wanpipe",
	26: "llc",
	27: "ib",
	28: "mpls",
	29: "can",
	30: "tipc",
	31: "bluetooth",
	32: "iucv",
	33: "rxrpc",
	34: "isdn",
	35: "phonet",
	36: "ieee802154",
	37: "caif",
	38: "alg",
	39: "nfc",
	40: "vsock",
	41: "kcm",
	42: "qipcrtr",
}

var architectures = map[string]uint32{
	"64bit":                 0x80000000,
	"little_endian":         0x40000000,
	"convention_mips64_n32": 0x20000000,
}

var machines = map[uint32]string{
	0:   "none",        // Unknown machine.
	1:   "m32",         // AT&T WE32100.
	2:   "sparc",       // Sun SPARC.
	3:   "386",         // Intel i386.
	4:   "68k",         // Motorola 68000.
	5:   "88k",         // Motorola 88000.
	7:   "860",         // Intel i860.
	8:   "mips",        // MIPS R3000 Big-Endian only.
	9:   "s370",        // IBM System/370.
	10:  "mips_rs3_le", // MIPS R3000 Little-Endian.
	15:  "parisc",      // HP PA-RISC.
	17:  "vpp500",      // Fujitsu VPP500.
	18:  "sparc32plus", // SPARC v8plus.
	19:  "960",         // Intel 80960.
	20:  "ppc",         // PowerPC 32-bit.
	21:  "ppc64",       // PowerPC 64-bit.
	22:  "s390",        // IBM System/390.
	36:  "v800",        // NEC V800.
	37:  "fr20",        // Fujitsu FR20.
	38:  "rh32",        // TRW RH-32.
	39:  "rce",         // Motorola RCE.
	40:  "arm",         // ARM.
	42:  "sh",          // Hitachi SH.
	43:  "sparcv9",     // SPARC v9 64-bit.
	44:  "tricore",     // Siemens TriCore embedded processor.
	45:  "arc",         // Argonaut RISC Core.
	46:  "h8_300",      // Hitachi H8/300.
	47:  "h8_300h",     // Hitachi H8/300H.
	48:  "h8s",         // Hitachi H8S.
	49:  "h8_500",      // Hitachi H8/500.
	50:  "ia_64",       // Intel IA-64 Processor.
	51:  "mips_x",      // Stanford MIPS-X.
	52:  "coldfire",    // Motorola ColdFire.
	53:  "68hc12",      // Motorola M68HC12.
	54:  "mma",         // Fujitsu MMA.
	55:  "pcp",         // Siemens PCP.
	56:  "ncpu",        // Sony nCPU.
	57:  "ndr1",        // Denso NDR1 microprocessor.
	58:  "starcore",    // Motorola Star*Core processor.
	59:  "me16",        // Toyota ME16 processor.
	60:  "st100",       // STMicroelectronics ST100 processor.
	61:  "tinyj",       // Advanced Logic Corp. TinyJ processor.
	62:  "x86_64",      // Advanced Micro Devices x86-64
	183: "aarch64",     // ARM 64-bit Architecture (AArch64)
}

var nonprintable = regexp.MustCompile(`[\0\200-\377]`)

var uids = []string{"uid", "auid", "euid", "fsuid", "suid"}

func parseArch(data map[string]interface{}) {
	if architecture, ok := data["arch"].(string); ok {
		v_arch := map[string]string{"bits": "", "endianness": "", "name": ""}
		if arch, err := strconv.ParseUint(architecture, 16, 32); err == nil {
			t_arch := uint32(arch)
			if t_arch&architectures["64bit"] != 0 {
				t_arch ^= architectures["64bit"]
				v_arch["bits"] = "64"
			} else {
				v_arch["bits"] = "32"
			}
			if t_arch&architectures["little_endian"] != 0 {
				t_arch ^= architectures["little_endian"]
				v_arch["endianness"] = "little"
			} else {
				v_arch["endianness"] = "big"
			}
			if t_arch&architectures["convention_mips64_n32"] != 0 {
				t_arch ^= architectures["convention_mips64_n32"]
			}
			if machine, ok := machines[t_arch]; ok {
				v_arch["name"] = machine
			}
		}
		data["arch"] = v_arch
	}
}

func mapUid(data map[string]interface{}, uidMap map[string]string, findUid string) {
	if foundUid, ok := data[findUid].(string); ok {
		if foundUid == "4294967295" {
			data[findUid] = nil
		} else {
			data[findUid] = map[string]string{"id": foundUid}
			if username, ok := uidMap[foundUid]; ok {
				data[findUid].(map[string]string)["name"] = username
			} else {
				data[findUid].(map[string]string)["name"] = "UNKNOWN_USER"
			}
		}
	}
}

func parseSockAddr(data map[string]interface{}, addr string) {
	length := len(addr)

	if length < 2 {
		data["unknown"] = addr
		return
	}

	if afBytes, err := hex.DecodeString(addr[0:4]); err != nil {
		data["unknown"] = addr
		return
	} else {

		af := binary.LittleEndian.Uint16(afBytes)
		data["family"] = addressFamiles[af]

		switch af {
		case 1: // local unix socket
			if length < 5 {
				data["unknown"] = addr[2:]
				break
			}
			i := strings.IndexAny(addr[4:], "00") - 4
			if i < 0 {
				i = length - 4
			}
			data["path"] = convertValue(addr[4 : 4+i])
			if length > i+5 {
				data["unknown"] = addr[i+4:]
			}

		case 2: // ipv4 socket
			if length < 16 {
				data["unknown"] = addr[2:]
				break
			}

			if port, err := strconv.ParseUint(addr[4:8], 16, 16); err == nil {
				data["port"] = port
			}

			var cidr []string

			for i := 8; i < 16; i = i + 2 {
				if octet, err := strconv.ParseUint(addr[i:i+2], 16, 8); err == nil {
					cidr = append(cidr, strconv.FormatUint(octet, 10))
				}
			}

			data["ip"] = strings.Join(cidr, ".")

			if length > 16 && strings.Trim(addr[16:], "0") != "" {
				data["unknown"] = addr[16:]
			}

		case 10: // ipv6 socket
			if length < 56 {
				data["unknown"] = addr[2:]
				break
			}

			if port, err := strconv.ParseUint(addr[4:8], 16, 16); err == nil {
				data["port"] = port
			}

			data["flow_info"] = addr[8:16]

			var cidr []string
			for i := 16; i < 48; i = i + 4 {
				cidr = append(cidr, addr[i:i+4])
			}
			data["ip"] = strings.Join(cidr, ":")
			data["scope_id"] = addr[48:56]

			if length > 56 {
				data["unknown"] = addr[56:]
			}

		default:
			data["unknown"] = addr[4:]
		}

	}

}

func parseField(data map[string]interface{}, field string) {
	if value, ok := data[field].(string); ok {
		data[field] = convertValue(value)
	}
}

func smashArgs(data map[string]interface{}, arg string, length string) {
	if _, ok := data[length]; ok {
		var value []string
		i := 0
		for {
			subArg := fmt.Sprintf("%s[%d]", arg, i)
			if val, ok := data[subArg].(string); ok {
				value = append(value, val)
				delete(data, subArg)
			} else {
				break
			}
			i += 1
		}

		data[arg] = strings.Join(value, "")
		delete(data, length)
	}
}

func convertValue(value string) string {
	if strings.HasPrefix(value, "\"") {
		return strings.Trim(value, "\"")
	} else if strings.Compare(value, "(null)") == 0 {
		return ""
	} else {
		if v, err := hex.DecodeString(value); err != nil {
			return value
		} else {
			return nonprintable.ReplaceAllString(string(v), " ")
		}
	}
	return value
}

func buildMessage(data map[string]interface{}) {
	var message []string

	if syscall, ok := data["syscall"].(map[string]interface{}); ok {

		if uid, ok := syscall["uid"].(map[string]string); ok {
			if auid, ok := syscall["auid"].(map[string]string); ok {
				if auid["id"] != uid["id"] {
					message = append(message, auid["name"], "as")
				}
			}
			message = append(message, uid["name"])
		}

		if success, ok := syscall["success"].(string); ok {
			if success == "yes" {
				message = append(message, "succeeded to")
			} else {
				message = append(message, "failed to")
			}
		}

		if name, ok := syscall["name"].(string); ok {
			message = append(message, name)
		}

		includeCmd := false
		var executable string

		if execve, ok := data["execve"].(map[string]interface{}); ok {
			if command, ok := execve["command"].(string); ok {
				if strings.Contains(command, " ") {
					command = command[:strings.Index(command, " ")]
				}
				if len(command) > 25 {
					command = command[:25]
				}
				message = append(message, command)
				if exe, ok := syscall["executable"].(string); ok {
					if exe != command {
						executable = exe
					}
				}
			}
		} else if name, ok := syscall["name"].(string); ok {
			switch name {
			case "bind", "connect", "sendto":
				includeCmd = true
				message = append(message, "to")
				if sockaddr, ok := data["sockaddr"].(map[string]interface{}); ok {
					if ip, ok := sockaddr["ip"].(string); ok {
						if port, ok := sockaddr["port"].(uint64); ok {
							message = append(message, fmt.Sprintf("`%s:%d`", ip, port))
						}
					} else if path, ok := sockaddr["path"].(string); ok {
						message = append(message, fmt.Sprintf("`%s`", path))
					} else {
						message = append(message, "`unknown address`")
					}
				}

			default:
				if paths, ok := data["path"].([]map[string]interface{}); ok {
					var created string
					var deleted string
					var normal string

					for _, path := range paths {
						if nametype, ok := path["nametype"].(string); ok {
							filename, ok := path["name"].(string)
							if !ok {
								inode := path["inode"].(string)
								filename = fmt.Sprintf("inode: %s", inode)
							}
							if nametype == "CREATE" && created == "" {
								created = filename
							} else if nametype == "DELETE" && deleted == "" {
								deleted = filename
							} else if nametype == "NORMAL" && normal == "" {
								normal = filename
							}
						}
					}

					if name == "rename" {
						message = append(message, fmt.Sprintf("`%s` to `%s`", deleted, created))
					} else if created != "" {
						message = append(message, fmt.Sprintf("and create `%s`", created))
					} else if normal != "" {
						message = append(message, fmt.Sprintf("`%s`", normal))
					} else {
						message = append(message, "`unknown path`")
					}
				}

			}
		}

		if executable != "" {
			message = append(message, "via", fmt.Sprintf("`%s`", executable))
		}

		if includeCmd {
			if command, ok := syscall["command"].(string); ok {
				message = append(message, "as", fmt.Sprintf("`%s`", command))
			}
		}

	}

	data["message"] = strings.TrimSpace(strings.Join(message, " "))

}

func parseMessage(amg *AuditMessageGroup, humanFriendly bool) map[string]interface{} {

	// The result ultimately holds our parsed AuditMessageGroup.
	// The structure makes use of map[string]interfaces{} types since
	// we don't know how deeply nested and what types values may be.
	result := map[string]interface{}{
		"timestamp": amg.AuditTime,
		"data": map[string]interface{}{
			"sequence": amg.Seq,
			"unknown":  []string{},
		},
		"error": nil,
	}

	data := result["data"].(map[string]interface{})
	msgs := make(map[uint16]interface{})

	// iterate over messages, grouping by message type
	// for all message types except for AUDIT_PATH (1302),
	// we join the grouped messages by space, and then split on space
	// we then split these values on equals sign, (max 1), and create a map
	for _, am := range amg.Msgs {
		switch am.Type {
		case AUDIT_PATH:
			if _, ok := msgs[am.Type]; !ok {
				msgs[am.Type] = []map[string]interface{}{}
			}

			entries := make(map[string]interface{})
			for _, fields := range strings.Split(am.Data, " ") {
				kv := strings.SplitN(fields, "=", 2)
				entries[kv[0]] = kv[1]
			}
			msgs[am.Type] = append(msgs[am.Type].([]map[string]interface{}), entries)

		default:
			if _, ok := msgs[am.Type]; !ok {
				msgs[am.Type] = make(map[string]interface{})
			}

			for _, fields := range strings.Split(am.Data, " ") {
				kv := strings.SplitN(fields, "=", 2)
				msgs[am.Type].(map[string]interface{})[kv[0]] = kv[1]
			}

		}
	}

	// remap some values, actually parsing different audit events into
	// more human-readable values
	for mType, msg := range msgs {
		switch mType {
		case AUDIT_SYSCALL, AUDIT_CONFIG_CHANGE:
			field := auditFriendlyNames[mType]
			m := msg.(map[string]interface{})
			data[field] = m

			for _, uid := range uids {
				mapUid(m, amg.UidMap, uid)
			}
			parseArch(m)

			if key, ok := m["key"].(string); ok {
				m["key"] = convertValue(key)
				delete(m, "key")
			}

			if syscall, ok := m["syscall"].(string); ok {
				// don't delete m["syscall"], since we reassign below
				m["id"] = syscall
				if i, err := strconv.ParseUint(syscall, 10, 16); err == nil {
					m["name"] = syscallNumbers[uint16(i)]
				}
			}

			if session_id, ok := m["ses"].(string); ok {
				m["session_id"] = session_id
				delete(m, "ses")
			}

			if cmd, ok := m["comm"].(string); ok {
				m["command"] = convertValue(cmd)
				delete(m, "comm")
			}

			if exe, ok := m["exe"].(string); ok {
				m["executable"] = convertValue(exe)
				delete(m, "exe")
			}

		case AUDIT_EXECVE:
			field := auditFriendlyNames[mType]
			m := msg.(map[string]interface{})
			data[field] = m

			if argc, ok := m["argc"].(string); ok {
				if nargs, err := strconv.ParseUint(argc, 10, 16); err == nil {
					var command []string
					var argFmt = "a%d"
					var argLen = "a%d_len"

					for arg := uint64(0); arg < nargs; arg++ {
						findArg := fmt.Sprintf(argFmt, arg)
						findArgLen := fmt.Sprintf(argLen, arg)
						smashArgs(m, findArg, findArgLen)

						if v, ok := m[findArg].(string); ok {
							argv := convertValue(v)
							command = append(command, argv)
							delete(m, findArg)
						}
					}

					m["command"] = strings.TrimSpace(strings.Join(command, " "))
				}
				delete(m, "argc")
			}

		case AUDIT_SOCKADDR:
			m := msg.(map[string]interface{})
			field := auditFriendlyNames[mType]
			data[field] = m

			if addr, ok := m["saddr"].(string); ok {
				parseSockAddr(m, addr)
				delete(m, "saddr")
			}

		case AUDIT_NETFILTER_CFG:
			m := msg.(map[string]interface{})
			field := auditFriendlyNames[mType]
			data[field] = m

			if family, ok := m["family"].(string); ok {
				if v, err := strconv.ParseUint(family, 10, 16); err != nil {
					if value, ok := addressFamiles[uint16(v)]; ok {
						m["family"] = value
					}
				}
			}

		case AUDIT_CWD, AUDIT_PROCTITLE:
			m := msg.(map[string]interface{})
			field := auditFriendlyNames[mType]
			data[field] = m
			parseField(m, field)

		case AUDIT_PATH:
			m := msg.([]map[string]interface{})
			field := auditFriendlyNames[mType]
			data[field] = m

			for _, path := range m {
				mapUid(path, amg.UidMap, "ouid")
				if name, ok := path["name"].(string); ok {
					path["name"] = convertValue(name)
				}
			}

		default:
			field := auditFriendlyNames[mType]
			m := msg.(map[string]interface{})
			data[field] = m
		}
	}

	if humanFriendly {
		buildMessage(data)
	}

	return result
}
