package main

import (
	"github.com/stretchr/testify/assert"
	"syscall"
	"testing"
	"time"
)

func TestAuditConstants(t *testing.T) {
	assert.Equal(t, 7, HEADER_MIN_LENGTH)
	assert.Equal(t, 6, HEADER_START_POS)
	assert.Equal(t, time.Second*2, COMPLETE_AFTER)
	assert.Equal(t, []byte{")"[0]}, headerEndChar)
}

func TestNewAuditMessage(t *testing.T) {
	msg := &syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(44),
			Type:  uint16(1309),
			Flags: uint16(0),
			Seq:   uint32(0),
			Pid:   uint32(0),
		},
		Data: []byte("audit(10000001:99): hi there"),
	}

	am := NewAuditMessage(msg)
	assert.Equal(t, uint16(1309), am.Type)
	assert.Equal(t, 99, am.Seq)
	assert.Equal(t, "10000001", am.AuditTime)
	assert.Equal(t, "hi there", am.Data)
}

func TestAuditMessageGroup_AddMessage(t *testing.T) {
	uidMap = make(map[string]string, 0)
	uidMap["0"] = "hi"
	uidMap["1"] = "nope"

	amg := &AuditMessageGroup{
		Seq:           1,
		AuditTime:     "ok",
		CompleteAfter: time.Now().Add(COMPLETE_AFTER),
		UidMap:        make(map[string]string, 2),
	}

	m := &AuditMessage{
		Data: "uid=0 things notuid=nopethisisnot",
	}

	amg.AddMessage(m)
	assert.Equal(t, 1, len(amg.Msgs), "Expected 1 message")
	assert.Equal(t, m, amg.Msgs[0], "First message was wrong")
	assert.Equal(t, 1, len(amg.UidMap), "Incorrect uid mapping count")
	assert.Equal(t, "hi", amg.UidMap["0"])

	// Make sure we don't parse uids for message types that don't have them
	m = &AuditMessage{
		Type: uint16(1309),
		Data: "uid=1",
	}
	amg.AddMessage(m)
	assert.Equal(t, 2, len(amg.Msgs), "Expected 2 messages")
	assert.Equal(t, m, amg.Msgs[1], "2nd message was wrong")
	assert.Equal(t, 1, len(amg.UidMap), "Incorrect uid mapping count")

	m = &AuditMessage{
		Type: uint16(1307),
		Data: "uid=1",
	}
	amg.AddMessage(m)
	assert.Equal(t, 3, len(amg.Msgs), "Expected 2 messages")
	assert.Equal(t, m, amg.Msgs[2], "3rd message was wrong")
	assert.Equal(t, 1, len(amg.UidMap), "Incorrect uid mapping count")
}

func TestNewAuditMessageGroup(t *testing.T) {
	uidMap = make(map[string]string, 0)
	m := &AuditMessage{
		Type:      uint16(1300),
		Seq:       1019,
		AuditTime: "9919",
		Data:      "Stuff is here",
	}

	amg := NewAuditMessageGroup(m)
	assert.Equal(t, 1019, amg.Seq)
	assert.Equal(t, "9919", amg.AuditTime)
	assert.True(t, amg.CompleteAfter.After(time.Now()), "Complete after time should be greater than right now")
	assert.Equal(t, 6, cap(amg.Msgs), "Msgs capacity should be 6")
	assert.Equal(t, 1, len(amg.Msgs), "Msgs should only have 1 message")
	assert.Equal(t, 0, len(amg.UidMap), "No uids in the original message")
	assert.Equal(t, m, amg.Msgs[0], "First message should be the original")
}

func Test_getUsername(t *testing.T) {
	uidMap = make(map[string]string, 0)
	assert.Equal(t, "root", getUsername("0"), "0 should be root you animal")
	assert.Equal(t, "UNKNOWN_USER", getUsername("-1"), "Expected UNKNOWN_USER")

	val, ok := uidMap["0"]
	if !ok {
		t.Fatal("Expected the uid mapping to be cached")
	}
	assert.Equal(t, "root", val)

	val, ok = uidMap["-1"]
	if !ok {
		t.Fatal("Expected the uid mapping to be cached")
	}
	assert.Equal(t, "UNKNOWN_USER", val)
}

func TestAuditMessageGroup_mapUids(t *testing.T) {
	uidMap = make(map[string]string, 0)
	uidMap["0"] = "hi"
	uidMap["1"] = "there"
	uidMap["2"] = "fun"
	uidMap["3"] = "test"
	uidMap["99999"] = "derp"

	amg := &AuditMessageGroup{
		Seq:           1,
		AuditTime:     "ok",
		CompleteAfter: time.Now().Add(COMPLETE_AFTER),
		UidMap:        make(map[string]string, 2),
	}

	m := &AuditMessage{
		Data: "uid=0 1uid=1 2uid=2 3uid=3 not here 4uid=99999",
	}
	amg.mapUids(m)

	assert.Equal(t, 5, len(amg.UidMap), "Uid map is too big")
	assert.Equal(t, "hi", amg.UidMap["0"])
	assert.Equal(t, "there", amg.UidMap["1"])
	assert.Equal(t, "fun", amg.UidMap["2"])
	assert.Equal(t, "test", amg.UidMap["3"])
	assert.Equal(t, "derp", amg.UidMap["99999"])
}

func Benchmark_getUsername(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = getUsername("0")
	}
}
