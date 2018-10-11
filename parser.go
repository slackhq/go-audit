package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	SYSCALL           = 1300            // Syscall event
	PATH              = 1302            // Filename path information
	IPC               = 1303            // IPC record
	SOCKETCALL        = 1304            // sys_socketcall arguments
	CONFIG_CHANGE     = 1305            // Audit system configuration change
	SOCKADDR          = 1306            // sockaddr copied as syscall arg
	CWD               = 1307            // Current working directory
	EXECVE            = 1309            // execve arguments
	IPC_SET_PERM      = 1311            // IPC new permissions record type
	MQ_OPEN           = 1312            // POSIX MQ open record type
	MQ_SENDRECV       = 1313            // POSIX MQ sendreceive record type
	MQ_NOTIFY         = 1314            // POSIX MQ notify record type
	MQ_GETSETATTR     = 1315            // POSIX MQ getset attribute record type
	KERNEL_OTHER      = 1316            // For use by 3rd party modules
	FD_PAIR           = 1317            // audit record for pipesocketpair
	OBJ_PID           = 1318            // ptrace target
	TTY               = 1319            // Input on an administrative TTY
	EOE               = 1320            // End of multi-record event
	BPRM_FCAPS        = 1321            // Information about fcaps increasing perms
	CAPSET            = 1322            // Record showing argument to sys_capset
	MMAP              = 1323            // Record showing descriptor and flags in mmap
	NETFILTER_PKT     = 1324            // Packets traversing netfilter chains
	NETFILTER_CFG     = 1325            // Netfilter chain modifications
	SECCOMP           = 1326            // Secure Computing event
	PROCTITLE         = 1327            // Proctitle emit event
	FEATURE_CHANGE    = 1328            // audit log listing feature changes
	REPLACE           = 1329            // Replace auditd if this packet unanswerd
	HEADER_MIN_LENGTH = 7               // Minimum length of an audit header
	HEADER_START_POS  = 6               // Position in the audit header that the data starts
	COMPLETE_AFTER    = time.Second * 2 // Log a message after this time or EOE
	SOCKADDR_LENGTH   = 34              // Length of saddr event
)

var uidMap = map[string]string{}
var headerEndChar = []byte{")"[0]}
var headerSepChar = byte(':')
var spaceChar = byte(' ')

type AuditMessage struct {
	Type      uint16 `json:"type"`
	Data      string `json:"data"`
	Seq       int    `json:"-"`
	AuditTime string `json:"-"`
}

type AuditMessageGroup struct {
	Seq           int               `json:"sequence"`
	AuditTime     string            `json:"timestamp"`
	CompleteAfter time.Time         `json:"-"`
	Msgs          []*AuditMessage   `json:"messages"`
	UidMap        map[string]string `json:"uid_map"`
	DnsMap        map[string]string `json:"dnstap"`
	Syscall       string            `json:"-"`
}

// Creates a new message group from the details parsed from the message
func NewAuditMessageGroup(am *AuditMessage) *AuditMessageGroup {
	//TODO: allocating 6 msgs per group is lame and we _should_ know ahead of time roughly how many we need
	amg := &AuditMessageGroup{
		Seq:           am.Seq,
		AuditTime:     am.AuditTime,
		CompleteAfter: time.Now().Add(COMPLETE_AFTER),
		UidMap:        make(map[string]string, 2), // Usually only 2 individual uids per execve
		DnsMap:        make(map[string]string, 1),
		Msgs:          make([]*AuditMessage, 0, 6),
	}

	amg.AddMessage(am)
	return amg
}

// Creates a new go-audit message from a netlink message
func NewAuditMessage(nlm *syscall.NetlinkMessage) *AuditMessage {
	aTime, seq := parseAuditHeader(nlm)
	return &AuditMessage{
		Type:      nlm.Header.Type,
		Data:      string(nlm.Data),
		Seq:       seq,
		AuditTime: aTime,
	}
}

// Gets the timestamp and audit sequence id from a netlink message
func parseAuditHeader(msg *syscall.NetlinkMessage) (time string, seq int) {
	headerStop := bytes.Index(msg.Data, headerEndChar)
	// If the position the header appears to stop is less than the minimum length of a header, bail out
	if headerStop < HEADER_MIN_LENGTH {
		return
	}

	header := string(msg.Data[:headerStop])
	if header[:HEADER_START_POS] == "audit(" {
		//TODO: out of range check, possibly fully binary?
		sep := strings.IndexByte(header, headerSepChar)
		time = header[HEADER_START_POS:sep]
		seq, _ = strconv.Atoi(header[sep+1:])

		// Remove the header from data
		msg.Data = msg.Data[headerStop+3:]
	}

	return time, seq
}

// Add a new message to the current message group
func (amg *AuditMessageGroup) AddMessage(am *AuditMessage) {
	amg.Msgs = append(amg.Msgs, am)
	//TODO: need to find more message types that won't contain uids, also make these constants
	switch am.Type {
	case EXECVE, CWD, SOCKADDR:
		amg.mapDns(am)
		// Don't map uids here
	case SYSCALL:
		amg.findSyscall(am)
		amg.mapUids(am)
	default:
		amg.mapUids(am)
	}
}

// Find all `saddr=` occurrences in a message and do a lookup
func (amg *AuditMessageGroup) mapDns(am *AuditMessage) {
	data := am.Data
	start := 0
	end := 0

	if start = strings.Index(data, "saddr="); start < 0 {
		return
	}

	// Progress the start point beyond the = sign
	start += 6
	if end = strings.IndexByte(data[start:], spaceChar); end < 0 {
		end = len(data) - start
		if end > SOCKADDR_LENGTH {
			return
		}
	}

	saddr := data[start : start+end]

	ip := parseAddr(saddr)

	host, ok := c.Get(ip)
	if ok {
		amg.DnsMap[ip] = host.(string)
	}
}

func parseAddr(saddr string) (addr string) {
	switch family := saddr[0:4]; family {
	// 0200: ipv4
	case "0200":
		octet, err := hex.DecodeString(saddr[8:16])
		if err != nil {
			el.Printf("unable to decode hex to ip: %s", err)
		}
		addr = fmt.Sprintf("%v.%v.%v.%v", octet[0], octet[1], octet[2], octet[3])
		// case "0A00":
		// 	octet, err := hex.DecodeString(saddr[16:48])
	}

	return addr
}

// Find all `uid=` occurrences in a message and adds the username to the UidMap object
func (amg *AuditMessageGroup) mapUids(am *AuditMessage) {
	data := am.Data
	start := 0
	end := 0

	for {
		if start = strings.Index(data, "uid="); start < 0 {
			break
		}

		// Progress the start point beyond the = sign
		start += 4
		if end = strings.IndexByte(data[start:], spaceChar); end < 0 {
			// There was no ending space, maybe the uid is at the end of the line
			end = len(data) - start

			// If the end of the line is greater than 5 characters away (overflows a 16 bit uint) then it can't be a uid
			if end > 5 {
				break
			}
		}

		uid := data[start : start+end]

		// Don't bother re-adding if the existing group already has the mapping
		if _, ok := amg.UidMap[uid]; !ok {
			amg.UidMap[uid] = getUsername(data[start : start+end])
		}

		// Find the next uid= if we have space for one
		next := start + end + 1
		if next >= len(data) {
			break
		}

		data = data[next:]
	}

}

func (amg *AuditMessageGroup) findSyscall(am *AuditMessage) {
	data := am.Data
	start := 0
	end := 0

	if start = strings.Index(data, "syscall="); start < 0 {
		return
	}

	// Progress the start point beyond the = sign
	start += 8
	if end = strings.IndexByte(data[start:], spaceChar); end < 0 {
		// There was no ending space, maybe the syscall id is at the end of the line
		end = len(data) - start

		// If the end of the line is greater than 5 characters away (overflows a 16 bit uint) then it can't be a syscall id
		if end > 5 {
			return
		}
	}

	amg.Syscall = data[start : start+end]
}

// Gets a username for a user id
func getUsername(uid string) string {
	uname := "UNKNOWN_USER"

	// Make sure we have a uid element to work with.
	// Give a default value in case we don't find something.
	if lUser, ok := uidMap[uid]; ok {
		uname = lUser
	} else {
		lUser, err := user.LookupId(uid)
		if err == nil {
			uname = lUser.Username
		}
		uidMap[uid] = uname
	}

	return uname
}
