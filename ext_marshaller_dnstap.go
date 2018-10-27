package main

import (
	"encoding/hex"
	"net"
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
	gotSaddr      map[int]bool
	gotDNS        map[int]bool
}

func NewDnsAuditMarshaller(am *AuditMarshaller) *DnsAuditMarshaller {
	cacheCfg := bigcache.Config{
		Shards:             256,
		LifeWindow:         time.Second * 300,
		MaxEntriesInWindow: 1024,
		MaxEntrySize:       96,
		HardMaxCacheSize:   10,
	}

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

	if ok && nlMsg.Header.Type == EVENT_EOE && (a.gotDNS[aMsg.Seq] || !a.gotSaddr[aMsg.Seq]) {
		a.completeMessage(aMsg.Seq)
		return
	}

	if ok {
		if aMsg.Type == SOCKADDR {
			a.mapDns(aMsg)
		}

		val.AddMessage(aMsg)

		// Mark if we don't have dns yet
		if a.gotSaddr[aMsg.Seq] && !a.gotDNS[aMsg.Seq] {
			ip, _ := a.mapDns(aMsg)
			a.waitingForDNS[ip] = val.Seq
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

	dnsAm.gotSaddr[am.Seq] = true

	var err error

	ip = parseAddr(saddr)
	port := parsePortIpv4(saddr)

	dnsAm.msgs[am.Seq].DnsMap["ip"] = ip
	dnsAm.msgs[am.Seq].DnsMap["port"] = strconv.FormatInt(port, 10)

	host, err = dnsAm.cache.Get(ip)
	if err == nil {
		dnsAm.gotDNS[am.Seq] = true
		dnsAm.msgs[am.Seq].DnsMap["record"] = string(host)
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

func parsePortIpv4(saddr string) int64 {
	a, err := strconv.ParseInt(saddr[4:6], 16, 32)
	if err != nil {
		el.Println(err)
	}

	b, err := strconv.ParseInt(saddr[6:8], 16, 32)
	if err != nil {
		el.Println(err)
	}

	return a*256 + b
}

func parseAddr(saddr string) (addr string) {
	family := parseFamily(saddr)
	//el.Println("FAM:", family)

	switch family {
	case 2:
		b, err := hex.DecodeString(saddr[8:16])
		if err != nil {
			el.Printf("unable to decode hex to bytes: %s", err)
		}
		addr = net.IP(b).String()
	}

	return addr
}
