package main

import (
	"syscall"
)

type DnsAuditMarshaller struct {
	*AuditMarshaller
	waitingForDNS map[string]int
}

func NewDnsAuditMarshaller(am *AuditMarshaller) *DnsAuditMarshaller {
	dam := &DnsAuditMarshaller{
		am,
		make(map[string]int),
	}

	return dam
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

	if ok && nlMsg.Header.Type == EVENT_EOE && (val.gotDNS || !val.gotSaddr) {
		a.completeMessage(aMsg.Seq)
		return
	}

	if ok {
		if aMsg.Type == SOCKADDR {
			val.mapDns(aMsg)
		}

		val.AddMessage(aMsg)

		// mark if we don't have dns yet
		if val.gotSaddr && !val.gotDNS {
			ip, _ := val.mapDns(aMsg)
			a.waitingForDNS[ip] = val.Seq
		}
	} else {
		// Create a new AuditMessageGroup
		a.msgs[aMsg.Seq] = NewAuditMessageGroup(aMsg)
	}

	a.flushOld()
}
