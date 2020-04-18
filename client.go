package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// Endianness is an alias for what we assume is the current machine endianness
var Endianness = binary.LittleEndian

const (
	// MAX_AUDIT_MESSAGE_LENGTH see http://lxr.free-electrons.com/source/include/uapi/linux/audit.h#L398
	MAX_AUDIT_MESSAGE_LENGTH = 8970
)

//TODO: this should live in a marshaller
type AuditStatusPayload struct {
	Mask            uint32
	Enabled         uint32
	Failure         uint32
	Pid             uint32
	RateLimit       uint32
	BacklogLimit    uint32
	Lost            uint32
	Backlog         uint32
	Version         uint32
	BacklogWaitTime uint32
}

// NetlinkPacket is an alias to give the header a similar name here
type NetlinkPacket unix.NlMsghdr

// NetlinkMessage is copied from syscall.NetlinkMessage as x/sys/unix does not have it
type NetlinkMessage struct {
	Header NetlinkPacket
	Data   []byte
}

type NetlinkClient struct {
	fd      int
	address unix.Sockaddr
	seq     uint32
	buf     []byte
}

// NewNetlinkClient creates a new NetLinkClient and optionally tries to modify the netlink recv buffer
func NewNetlinkClient(recvSize int) (*NetlinkClient, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_AUDIT)
	if err != nil {
		return nil, fmt.Errorf("Could not create a socket: %s", err)
	}

	n := &NetlinkClient{
		fd:      fd,
		address: &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 0, Pid: 0},
		buf:     make([]byte, MAX_AUDIT_MESSAGE_LENGTH),
	}

	if err = unix.Bind(fd, n.address); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("Could not bind to netlink socket: %s", err)
	}

	// Set the buffer size if we were asked
	if recvSize > 0 {
		if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, recvSize); err != nil {
			el.Println("Failed to set receive buffer size")
		}
	}

	// Print the current receive buffer size
	if v, err := unix.GetsockoptInt(n.fd, unix.SOL_SOCKET, unix.SO_RCVBUF); err == nil {
		l.Println("Socket receive buffer size:", v)
	}

	go func() {
		for {
			n.KeepConnection()
			time.Sleep(time.Second * 5)
		}
	}()

	return n, nil
}

// Send will send a packet and payload to the netlink socket without waiting for a response
func (n *NetlinkClient) Send(np *NetlinkPacket, a *AuditStatusPayload) error {
	//We need to get the length first. This is a bit wasteful, but requests are rare so yolo..
	buf := new(bytes.Buffer)
	var length int

	np.Seq = atomic.AddUint32(&n.seq, 1)

	for {
		buf.Reset()
		binary.Write(buf, Endianness, np)
		binary.Write(buf, Endianness, a)
		if np.Len == 0 {
			length = len(buf.Bytes())
			np.Len = uint32(length)
		} else {
			break
		}
	}

	if err := unix.Sendto(n.fd, buf.Bytes(), 0, n.address); err != nil {
		return err
	}

	return nil
}

// Receive will receive a packet from a netlink socket
func (n *NetlinkClient) Receive() (*NetlinkMessage, error) {
	nlen, _, err := unix.Recvfrom(n.fd, n.buf, 0)
	if err != nil {
		return nil, err
	}

	if nlen < 1 {
		return nil, errors.New("Got a 0 length packet")
	}

	msg := &NetlinkMessage{
		Header: NetlinkPacket{
			Len:   Endianness.Uint32(n.buf[0:4]),
			Type:  Endianness.Uint16(n.buf[4:6]),
			Flags: Endianness.Uint16(n.buf[6:8]),
			Seq:   Endianness.Uint32(n.buf[8:12]),
			Pid:   Endianness.Uint32(n.buf[12:16]),
		},
		Data: n.buf[unix.SizeofNlMsghdr:nlen],
	}

	return msg, nil
}

// KeepConnection re-establishes our connection to the netlink socket
func (n *NetlinkClient) KeepConnection() {
	payload := &AuditStatusPayload{
		Mask:    4,
		Enabled: 1,
		Pid:     uint32(unix.Getpid()),
		//TODO: Failure: http://lxr.free-electrons.com/source/include/uapi/linux/audit.h#L338
	}

	packet := &NetlinkPacket{
		Type:  uint16(1001),
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Pid:   uint32(unix.Getpid()),
	}

	err := n.Send(packet, payload)
	if err != nil {
		el.Println("Error occurred while trying to keep the connection:", err)
	}
}
