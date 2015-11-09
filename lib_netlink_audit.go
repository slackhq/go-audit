package main

import (
	"bytes"
	"encoding/binary"
	//"fmt"
	"sync/atomic"
	"syscall"
)

const (
	MAX_AUDIT_MESSAGE_LENGTH = 8970
	AUDIT_SYSCALL            = 1300
	AUDIT_EOE                = 1320
)

var Endianness = binary.LittleEndian
var sequenceNumber uint32

//An alias to give the header a similar name here
type NetlinkPacket syscall.NlMsghdr

//This is the struct for an "audit_status" message.
//Found here: https://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/tree/include/uapi/linux/audit.h?h=linux-3.14.y#n375
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

type NetlinkConnection struct {
	fd      int
	address syscall.SockaddrNetlink
}

//This is the structure of a complete Netlink Audit packet.
type AuditRequest struct {
	n NetlinkPacket
	a AuditStatusPayload
}

func readNetlinkPacketHeader(data []byte) NetlinkPacket {
	b := NetlinkPacket{}
	buf := bytes.NewReader(data)
	binary.Read(buf, Endianness, &b)
	return b
}

//Generates a fresh netlinkpacket object, which is the base packet for talking to the kernel
func newNetlinkPacket(htype int) (n *NetlinkPacket) {
	n = &NetlinkPacket{}
	n.Type = uint16(htype)
	n.Flags = syscall.NLM_F_REQUEST | syscall.NLM_F_ACK
	n.Seq = atomic.AddUint32(&sequenceNumber, 1)
	n.Pid = uint32(syscall.Getpid())
	return n
}

func newAuditStatusPayload() (*AuditStatusPayload, error) {
	a := &AuditStatusPayload{}
	return a, nil
}

func AuditRequestSerialize(n *NetlinkPacket, a *AuditStatusPayload) (data []byte, err error) {
	//We need to get the length first. This is a bit wasteful, but requests are rare so yolo..
	buf := new(bytes.Buffer)
	var length int
	for {
		buf.Reset()
		binary.Write(buf, Endianness, n)
		binary.Write(buf, Endianness, a)
		if n.Len == 0 {
			length = len(buf.Bytes())
			n.Len = uint32(length)
		} else {
			break
		}
	}
	return buf.Bytes(), err
}

//Creates a fresh connection and returns AuditConnection
func newNetlinkConnection() (*NetlinkConnection, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_AUDIT)
	var _ = err
	if err != nil {
		return nil, err
	}

	n := &NetlinkConnection{}
	n.fd = fd
	n.address = syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: 0, Pid: 0}
	//fmt.Println(n.address)

	if err = syscall.Bind(fd, &n.address); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	return n, nil
}

func (n *NetlinkConnection) Send(packet *[]byte) error {
	if err := syscall.Sendto(n.fd, *packet, 0, &n.address); err != nil {
		return err
	}
	return nil
}

func (n *NetlinkConnection) Receive() ([]byte, error) {
	rb := make([]byte, MAX_AUDIT_MESSAGE_LENGTH)
	nlen, _, err := syscall.Recvfrom(n.fd, rb, 0)
	return rb[:nlen], err

}

func (n *NetlinkConnection) Close() {
	syscall.Close(n.fd)
}
