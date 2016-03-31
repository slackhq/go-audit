package main

import (
	"bytes"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var uidMap = map[string]user.User{}
var headerEndChar = []byte{")"[0]}

const (
	HEADER_MIN_LENGTH = 7               // Minimum length of an audit header
	HEADER_START_POS  = 6               // Position in the audit header that the data starts
	COMPLETE_AFTER    = time.Second * 2 // Log a message after this time or EOE
)

type AuditMessage struct {
	Type uint16 `json:"type"`
	Data string `json:"data"`
	Seq int `json:"-"`
	AuditTime string `json:"-"`
}

type AuditMessageGroup struct {
	Seq           int `json:"sequence"`
	AuditTime     string `json:"timestamp"`
	CompleteAfter time.Time `json:"-"`
	Msgs          []*AuditMessage `json:"messages"`
	UidMap        map[string]string `json:"uid_map"`
}

func NewAuditMessageGroup(am *AuditMessage) *AuditMessageGroup {
	//TODO: allocating 6 msgs per group is lame and we _should_ know ahead of time roughly how many we need
	amg := &AuditMessageGroup{
		Seq:           am.Seq,
		AuditTime:     am.AuditTime,
		CompleteAfter: time.Now().Add(COMPLETE_AFTER),
		Msgs:          make([]*AuditMessage, 6), // 6 msgs per execve is common
		UidMap:        make(map[string]string, 2), // Usually only 2 individual uids per execve
	}

	amg.AddMessage(am)
	return amg
}

func NewAuditMessage(nlm *syscall.NetlinkMessage) *AuditMessage {
	aTime, seq := parseAuditHeader(nlm)
	return &AuditMessage{
		Type: nlm.Header.Type,
		Data: string(nlm.Data),
		Seq: seq,
		AuditTime: aTime,
	}
}

func parseAuditHeader(msg *syscall.NetlinkMessage) (time string, seq int) {
	headerStop := bytes.Index(msg.Data, headerEndChar)
	// If the position the header appears to stop is less than the minimum length of a header, bail out
	if headerStop < HEADER_MIN_LENGTH {
		return
	}

	header := string(msg.Data[:headerStop])
	if header[:HEADER_START_POS] == "audit(" {
		//TODO: out of range check, possibly fully binary?
		sep := strings.IndexByte(header, ":"[0])
		time = header[HEADER_START_POS:sep]
		seq, _ = strconv.Atoi(header[sep + 1:])

		// Remove the header from data
		msg.Data = msg.Data[headerStop+2:]
	}

	return time, seq
}

func (amg *AuditMessageGroup) AddMessage(am *AuditMessage) {
	amg.Msgs = append(amg.Msgs, am)
	amg.mapUids(am)
}

//This takes the map to modify and a key name and adds the username to a new key with "_username"
func (amg *AuditMessageGroup) mapUids(am *AuditMessage) {
	data := am.Data
	start := 0
	end := 0

	for {
		if start = strings.Index(data, "uid="); start < 0 {
			break
		}

		start += 4
		if end = strings.IndexByte(data[start:], " "[0]); end < 0 {
			break
		}

		uid := data[start:start + end]
		// Don't bother re-adding if the existing group already has the mapping
		if _, ok := amg.UidMap[uid]; !ok {
			amg.UidMap[uid] = findUid(data[start:start + end])
		}

		next := start + end + 1
		if (next >= len(data)) {
			break
		}
		data = data[next:]
	}

}

func findUid(uid string) (string) {
	uname := "UNKNOWN_USER"

	//Make sure we have a uid element to work with.
	//Give a default value in case we don't find something.
	if lUser, ok := uidMap[uid]; ok {
		uname = lUser.Username
	} else {
		lUser, err := user.LookupId(uid)
		if err == nil {
			uname = lUser.Username
			uidMap[uid] = *lUser
		} else {
			uidMap[uid] = user.User{Username: uname}
		}
	}

	return uname
}
