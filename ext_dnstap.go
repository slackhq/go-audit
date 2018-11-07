package main

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/dnstap/golang-dnstap"
	"github.com/farsightsec/golang-framestream"
	"github.com/golang/protobuf/proto"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

type DnsTapClient struct {
	Listener           net.Listener
	DnsAuditMarshaller *DnsAuditMarshaller
}

func NewDnsTapClient(config *viper.Viper, am *DnsAuditMarshaller) (*DnsTapClient, error) {
	socket := config.GetString("dnstap.socket")
	os.Remove(socket)

	listener, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("Listen error: %s", err)
	}

	socketOwner := config.GetString("dnstap.socket_owner")

	u, err := user.Lookup(socketOwner)
	if err != nil {
		return nil, fmt.Errorf("Could not find uid for user %s. Error: %s", socketOwner, err)
	}

	uid, err := strconv.ParseInt(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("Found uid could not be parsed. Error: %s", err)
	}

	g, err := user.LookupGroup(socketOwner)
	if err != nil {
		return nil, fmt.Errorf("Could not find gid for group %s. Error: %s", socketOwner, err)
	}

	gid, err := strconv.ParseInt(g.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("Found gid could not be parsed. Error: %s", err)
	}

	if err = os.Chown(socket, int(uid), int(gid)); err != nil {
		return nil, fmt.Errorf("Could not chown output file. Error: %s", err)
	}

	d := &DnsTapClient{
		Listener:           listener,
		DnsAuditMarshaller: am,
	}
	el.Printf("Started dnstap listener, opened input socket: %s", socket)
	return d, nil
}

func (d *DnsTapClient) Receive() {
	defer d.Listener.Close()
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
			host := strings.TrimRight(r.Header().Name, ".")
			switch m.Answer[i].Header().Rrtype {
			case dns.TypeA:
				ipv4 := m.Answer[i].(*dns.A).A.String()
				d.DnsAuditMarshaller.cache.Set(ipv4, []byte(host))
				if seq, ok := d.DnsAuditMarshaller.waitingForDNS[ipv4]; ok {
					if msg, ok := d.DnsAuditMarshaller.msgs[seq]; ok {
						if !d.DnsAuditMarshaller.GotDNS[seq] && d.DnsAuditMarshaller.GotSaddr[seq] {
							d.DnsAuditMarshaller.getDNS(msg)
						}
						d.DnsAuditMarshaller.completeMessage(seq)
					}
					delete(d.DnsAuditMarshaller.waitingForDNS, ipv4)
				}
			case dns.TypeAAAA:
				ipv6 := m.Answer[i].(*dns.AAAA).AAAA.String()
				d.DnsAuditMarshaller.cache.Set(ipv6, []byte(host))
			case dns.TypeCNAME:
				cname := m.Answer[i].(*dns.CNAME).Target
				d.DnsAuditMarshaller.cache.Set(cname, []byte(host))
				//el.Printf("Setting cname for %s -> %s @ %v", host, cname, time.Now().Unix())
			}

		}
	}
}

func (dnsAm *DnsAuditMarshaller) getDNS(val *AuditMessageGroup) (ip string, host []byte) {
	for _, msg := range val.Msgs {
		if msg.Type == SOCKADDR {
			ip, host = dnsAm.mapDns(msg)
		}
	}
	return ip, host
}
