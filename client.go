package main

import (
	"syscall"
	"log"
	"sync/atomic"
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
	"errors"
)

var Endianness = binary.LittleEndian

const (
	//http://lxr.free-electrons.com/source/include/uapi/linux/audit.h#L398
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

//An alias to give the header a similar name here
type NetlinkPacket syscall.NlMsghdr

type NetlinkClient struct {
	fd             int
	address        syscall.SockaddrNetlink
	seq            uint32
	buf            []byte
}

func NewNetlinkClient(recvSize int) (*NetlinkClient) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_AUDIT)
	if err != nil {
		log.Fatal("Could not create a socket:", err)
	}

	n := &NetlinkClient{
		fd: fd,
		address: syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: 0, Pid: 0},
		buf:     make([]byte, MAX_AUDIT_MESSAGE_LENGTH),
	}

	if err = syscall.Bind(fd, &n.address); err != nil {
		syscall.Close(fd)
		log.Fatal("Could not bind to netlink socket:", err)
	}

	// Set the buffer size if we were asked
	if (recvSize > 0) {
		err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, recvSize)
	}

	// Print the current receive buffer size
	if v, err := syscall.GetsockoptInt(n.fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF); err == nil {
		fmt.Println("Socket receive buffer size:", v)
	}

	go n.KeepConnection()

	return n
}

func (n *NetlinkClient) Send(packet *[]byte) error {
	if err := syscall.Sendto(n.fd, *packet, 0, &n.address); err != nil {
		return err
	}
	return nil
}

func (n *NetlinkClient) Receive() (*syscall.NetlinkMessage, error) {
	nlen, _, err := syscall.Recvfrom(n.fd, n.buf, 0)
	if err != nil {
		return nil, err
	}

	if nlen < 1 {
		return nil, errors.New("Got a 0 length packet")
	}

	msg := &syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len: Endianness.Uint32(n.buf[0:4]),
			Type: Endianness.Uint16(n.buf[4:6]),
			Flags: Endianness.Uint16(n.buf[6:8]),
			Seq: Endianness.Uint32(n.buf[8:12]),
			Pid: Endianness.Uint32(n.buf[12:16]),
		},
		Data: n.buf[syscall.SizeofNlMsghdr:nlen],
	}

	return msg, nil
}

func (n *NetlinkClient) KeepConnection() {
	for {
		var ret []byte

		payload := &AuditStatusPayload{
			Mask: 4,
			Enabled: 1,
			Pid: uint32(syscall.Getpid()),
			//TODO: Failure: http://lxr.free-electrons.com/source/include/uapi/linux/audit.h#L338
		}

		packet := &NetlinkPacket{
			Type: uint16(1001),
			Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
			Seq: atomic.AddUint32(&n.seq, 1),
			Pid: uint32(syscall.Getpid()),
		}

		ret, _ = AuditRequestSerialize(packet, payload)

		err := n.Send(&ret)
		if err != nil {
			fmt.Println("Error occurred while trying to keep the connection:", err)
		}

		time.Sleep(time.Second * 5)
	}
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
