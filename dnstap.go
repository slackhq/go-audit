package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/dnstap/golang-dnstap"
	"github.com/farsightsec/golang-framestream"
	"github.com/golang/protobuf/proto"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
)

const defaultTimeout = time.Hour

var c = cache.New(defaultTimeout, defaultTimeout*2)

type DnsTapClient struct {
	Listener net.Listener
	//Cache    *cache.Cache
}

func NewDnsTapClient(socket string) (*DnsTapClient, error) {
	os.Remove(socket)
	//c := cache.New(defaulTimeout, defaulTimeout *2)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("Listen error: ", err)
	}
	d := &DnsTapClient{
		Listener: listener,
		//Cache: c,
	}
	l.Printf("Started dnstap listener, opened input socket: %s", socket)
	return d, nil
}

func (d *DnsTapClient) Receive() {
	for {
		conn, err := d.Listener.Accept()
		if err != nil {
			el.Printf("net.Listener.Accept() failed: %s\n", err)
			continue
		}
		go d.Decode(conn)
	}
}

func (d *DnsTapClient) Decode(conn net.Conn) {
	decoderOptions := &framestream.DecoderOptions{
		ContentType:   []byte("protobuf:dnstap.Dnstap"),
		Bidirectional: true,
	}
	dec, err := framestream.NewDecoder(conn, decoderOptions)
	if err != nil {
		el.Printf("framestream.NewDecoder failed: %s\n", err)
	}
	for {
		frame, err := dec.Decode()
		if err != nil {
			el.Printf("framestream.Decoder.Decode() failed: %s\n", err)
			break
		}
		dt := &dnstap.Dnstap{}
		if err := proto.Unmarshal(frame, dt); err != nil {
			el.Printf("dnstap.DnsOutput: proto.Unmarshal() failed: %s\n", err)
			break
		}
		if dt.Message.ResponseMessage != nil {
			d.cache(dt)
		}
	}
}

func (d *DnsTapClient) cache(dt *dnstap.Dnstap) {
	m := new(dns.Msg)
	err := m.Unpack(dt.Message.ResponseMessage)
	if err != nil {
		el.Printf("msg.Unpack() failed: %s \n", err)
	} else {
		for i, r := range m.Answer {
			switch m.Answer[i].Header().Rrtype {
			case dns.TypeA:
				ip := m.Answer[i].(*dns.A).A.String()
				host := strings.TrimRight(r.Header().Name, ".")
				c.Set(ip, host, defaultTimeout)
			}
		}
	}
}
