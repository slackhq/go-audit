package main

import (
	"encoding/hex"
	"net"

	"os"
	"strconv"
	"syscall"
	"time"

	"strings"

	"github.com/allegro/bigcache"
)

type DnsAuditMarshaller struct {
	*AuditMarshaller
	waitingForDNS map[string]int
	cache         *bigcache.BigCache
	GotSaddr      map[int]bool
	GotDNS        map[int]bool
}

func NewDnsAuditMarshaller(am *AuditMarshaller, cacheCfg bigcache.Config) *DnsAuditMarshaller {
	c, cacheInitErr := bigcache.NewBigCache(cacheCfg)

	if cacheInitErr != nil {
		el.Fatal(cacheInitErr)
	}

	dnsAm := &DnsAuditMarshaller{
		am,
		make(map[string]int),
		c,
		make(map[int]bool),
		make(map[int]bool),
	}

	return dnsAm
}

// Ingests a netlink message and likely prepares it to be logged
func (a *DnsAuditMarshaller) Consume(nlMsg *syscall.NetlinkMessage) {
	aMsg := NewAuditMessage(nlMsg)

	if aMsg.Seq == 0 {
		// We got an invalid audit message, return the current message and reset
		a.flushOld()
		return
	}

	if a.trackMessages {
		a.detectMissing(aMsg.Seq)
	}

	if nlMsg.Header.Type < a.eventMin || nlMsg.Header.Type > a.eventMax {
		// Drop all audit messages that aren't things we care about or end a multi packet event
		a.flushOld()
		return
	}

	val, ok := a.msgs[aMsg.Seq]

	if ok && nlMsg.Header.Type == EVENT_EOE && (a.GotDNS[aMsg.Seq] || !a.GotSaddr[aMsg.Seq]) {
		a.completeMessage(aMsg.Seq)
		return
	}

	if ok {
		if aMsg.Type == SOCKADDR {
			a.mapDns(aMsg)
		}

		// Mark if we don't have dns yet
		if a.GotSaddr[aMsg.Seq] && !a.GotDNS[aMsg.Seq] {
			ip, _ := a.mapDns(aMsg)
			a.waitingForDNS[ip] = val.Seq
		}

		if aMsg.Type != EVENT_EOE {
			val.AddMessage(aMsg)
		}

	} else {
		// Create a new AuditMessageGroup
		a.msgs[aMsg.Seq] = NewAuditMessageGroup(aMsg)
	}

	a.flushOld()
}

// Find all `saddr=` occurrences in a message and do a lookup
func (dnsAm *DnsAuditMarshaller) mapDns(am *AuditMessage) (ip string, host []byte) {
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

	dnsAm.GotSaddr[am.Seq] = true

	var err error

	ip = parseAddr(saddr)

	host, err = dnsAm.cache.Get(ip)
	if err == nil {
		dnsAm.msgs[am.Seq].DnsMap[ip] = string(host)
	}
	return
}

func parseFamily(saddr string) int64 {
	a, err := strconv.ParseInt(saddr[0:2], 16, 32)
	if err != nil {
		el.Println(err)
	}

	b, err := strconv.ParseInt(saddr[2:4], 16, 32)
	if err != nil {
		el.Println(err)
	}

	return a + 256*b

}

func parseAddr(saddr string) (addr string) {
	family := parseFamily(saddr)

	switch family {
	case AF_INET:
		b, err := hex.DecodeString(saddr[8:16])
		if err != nil {
			el.Printf("unable to decode hex to bytes: %s", err)
		}
		addr = net.IP(b).String()
	}

	return addr
}

func (a *DnsAuditMarshaller) completeMessage(seq int) {
	var msg *AuditMessageGroup
	var ok bool

	if msg, ok = a.msgs[seq]; !ok {
		//TODO: attempted to complete a missing message, log?
		return
	}

	if a.GotSaddr[seq] && !a.GotDNS[seq] {
		a.getDNS(msg)
	}

	if a.dropMessage(msg) {
		delete(a.msgs, seq)
		return
	}

	if err := a.writer.Write(msg); err != nil {
		el.Println("Failed to write message. Error:", err)
		os.Exit(1)
	}

	delete(a.msgs, seq)
}

// Outputs any messages that are old enough
// This is because there is no indication of multi message events coming from kaudit
func (a *DnsAuditMarshaller) flushOld() {
	now := time.Now()
	for seq, msg := range a.msgs {
		if msg.CompleteAfter.Before(now) || now.Equal(msg.CompleteAfter) {
			a.completeMessage(seq)
		}
	}
}
