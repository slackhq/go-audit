package main

import (
	"bytes"
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMarshallerConstants(t *testing.T) {
	assert.Equal(t, 1320, EVENT_EOE)
}

func TestAuditMarshaller_Consume(t *testing.T) {
	w := &bytes.Buffer{}
	m := NewAuditMarshaller(NewAuditWriter(w, 1), uint16(1100), uint16(1399), false, false, 0, []AuditFilter{})

	// Flush group on 1320
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(44),
			Type:  uint16(1300),
			Flags: uint16(0),
			Seq:   uint32(0),
			Pid:   uint32(0),
		},
		Data: []byte("audit(10000001:1): hi there"),
	})

	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(44),
			Type:  uint16(1301),
			Flags: uint16(0),
			Seq:   uint32(0),
			Pid:   uint32(0),
		},
		Data: []byte("audit(10000001:1): hi there"),
	})

	m.Consume(new1320("1"))

	assert.Equal(
		t,
		"{\"sequence\":1,\"timestamp\":\"10000001\",\"messages\":[{\"type\":1300,\"data\":\"hi there\"},{\"type\":1301,\"data\":\"hi there\"}],\"uid_map\":{}}\n",
		w.String(),
	)
	assert.Equal(t, 0, len(m.msgs))

	// Ignore below 1100
	w.Reset()
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(44),
			Type:  uint16(1099),
			Flags: uint16(0),
			Seq:   uint32(0),
			Pid:   uint32(0),
		},
		Data: []byte("audit(10000001:2): hi there"),
	})

	assert.Equal(t, 0, len(m.msgs))

	// Ignore above 1399
	w.Reset()
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(44),
			Type:  uint16(1400),
			Flags: uint16(0),
			Seq:   uint32(0),
			Pid:   uint32(0),
		},
		Data: []byte("audit(10000001:3): hi there"),
	})

	assert.Equal(t, 0, len(m.msgs))

	// Ignore sequences of 0
	w.Reset()
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(44),
			Type:  uint16(1400),
			Flags: uint16(0),
			Seq:   uint32(0),
			Pid:   uint32(0),
		},
		Data: []byte("audit(10000001:0): hi there"),
	})

	assert.Equal(t, 0, len(m.msgs))

	// Should flush old msgs after 2 seconds
	w.Reset()
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(44),
			Type:  uint16(1300),
			Flags: uint16(0),
			Seq:   uint32(0),
			Pid:   uint32(0),
		},
		Data: []byte("audit(10000001:4): hi there"),
	})

	start := time.Now()
	for len(m.msgs) != 0 {
		m.Consume(new1320("0"))
	}

	assert.Equal(t, "{\"sequence\":4,\"timestamp\":\"10000001\",\"messages\":[{\"type\":1300,\"data\":\"hi there\"}],\"uid_map\":{}}\n", w.String())
	expected := start.Add(time.Second * 2)
	assert.True(t, expected.Equal(time.Now()) || expected.Before(time.Now()), "Should have taken at least 2 seconds to flush")
	assert.Equal(t, 0, len(m.msgs))
}

func TestAuditMarshaller_completeMessage(t *testing.T) {
	//TODO: cant test because completeMessage calls exit
	t.Skip()
	return
	// lb, elb := hookLogger()
	// m := NewAuditMarshaller(NewAuditWriter(&FailWriter{}, 1), uint16(1300), uint16(1399), false, false, 0, []AuditFilter{})

	// m.Consume(&syscall.NetlinkMessage{
	// 	Header: syscall.NlMsghdr{
	// 		Len:   uint32(44),
	// 		Type:  uint16(1300),
	// 		Flags: uint16(0),
	// 		Seq:   uint32(0),
	// 		Pid:   uint32(0),
	// 	},
	// 	Data: []byte("audit(10000001:4): hi there"),
	// })

	// m.completeMessage(4)
	// assert.Equal(t, "!", lb.String())
	// assert.Equal(t, "!", elb.String())
}

func new1320(seq string) *syscall.NetlinkMessage {
	return &syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(44),
			Type:  uint16(1320),
			Flags: uint16(0),
			Seq:   uint32(0),
			Pid:   uint32(0),
		},
		Data: []byte("audit(10000001:" + seq + "): "),
	}
}

type FailWriter struct{}

func (f *FailWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("derp")
}
