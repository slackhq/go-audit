package main

import (
	"net"
	"os"
	"time"

	"github.com/dnstap/golang-dnstap"
	"github.com/farsightsec/golang-framestream"
	"github.com/golang/protobuf/proto"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
)

const defaulTimeout = 24 * time.Hour

var c = cache.New(defaulTimeout, defaulTimeout*2)

type DNSTap struct {
	Listener net.Listener
	//Cache    *cache.Cache
}

func NewDNSTap(socketPath string) (*DNSTap, error) {
	os.Remove(socketPath)
	//c := cache.New(defaulTimeout, defaulTimeout *2)
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		el.Fatal("Listen error: ", err)
	}
	d := &DNSTap{
		Listener: l,
		//Cache: c,
	}
	return d, nil
}

func (d *DNSTap) readSock() {
	for {
		conn, err := d.Listener.Accept()
		if err != nil {
			el.Printf("net.Listener.Accept() failed: %s\n", err)
			continue
		}
		go d.frameDecode(conn)
	}
}

func (d *DNSTap) frameDecode(conn net.Conn) {
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
			el.Fatalf("framestream.Decoder.Decode() failed: %s\n", err)
			break
		}
		dt := &dnstap.Dnstap{}
		if err := proto.Unmarshal(frame, dt); err != nil {
			el.Fatalf("dnstap.DnsOutput: proto.Unmarshal() failed: %s\n", err)
			break
		}
		if *dt.Type == dnstap.Dnstap_MESSAGE {
			msg := new(dns.Msg)
			if dt.Message.ResponseMessage != nil {
				err := msg.Unpack(dt.Message.ResponseMessage)
				if err != nil {
					el.Fatalf("msg.Unpack:() failed: %s \n", err)
				} else {
					d.storeDNSRec(msg)
				}
			}
		}
	}
}

func (d *DNSTap) storeDNSRec(msg *dns.Msg) {
	for i, rr := range msg.Answer {
		if msg.Answer[i].Header().Rrtype == dns.TypeA {
			ipAddr := msg.Answer[i].(*dns.A).A.String()
			hostname := rr.Header().Name
			c.Set(ipAddr, hostname, defaulTimeout)
		}

	}
}
