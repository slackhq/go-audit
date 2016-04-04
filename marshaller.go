package main

//TODO: need a repro case for combo breaking packets
//AKA multiline msg is coming in and next seq breaks the combo

import (
	"encoding/json"
	"log"
	"time"
	"syscall"
	"fmt"
)

const (
	EVENT_START = 1300 // Start of the audit type ids that we care about
	EVENT_END = 1399 // End of the audit type ids that we care about
	EVENT_EOE = 1320 // End of multi packet event
)

type AuditLogger interface {
	Write([]byte) (int, error)
}

type AuditMarshaller struct {
	msgs map[int]*AuditMessageGroup
	al AuditLogger
	lastSeq int
	buf []byte
}

// Create a new marshaller
func NewAuditMarshaller(al AuditLogger) (*AuditMarshaller){
	return &AuditMarshaller{
		al: al,
		msgs: make(map[int]*AuditMessageGroup, 5), // It is not typical to have more than 2 messagee groups at any given time
	}
}

// Ingests a netlink message and likely prepares it to be logged
func (a *AuditMarshaller) Consume(nlMsg *syscall.NetlinkMessage) {
	//TODO: currently message completion requires the canary, make the client shoot noop messages occasionally to flush this
	aMsg := NewAuditMessage(nlMsg)

	if aMsg.Seq == 0 {
		// We got an invalid audit message, return the current message and reset
		a.flushOld()
		return
	}

	if aMsg.Seq > a.lastSeq + 1 && a.lastSeq != 0 {
		// Detect if we lost any messages
		fmt.Printf("Likely missed a packet, last seen: %s; current %s;\n", a.lastSeq, aMsg.Seq)
	}

	if aMsg.Seq > a.lastSeq {
		// Keep track of the largest sequence
		a.lastSeq = aMsg.Seq
	}

	if (nlMsg.Header.Type < EVENT_START || nlMsg.Header.Type > EVENT_END) {
		// Drop all audit messages that aren't things we care about or end a multi packet event
		a.flushOld()
		return
	} else if nlMsg.Header.Type == EVENT_EOE {
		// This is end of event msg, flush the msg with that sequence and discard this one
		a.completeMessage(aMsg.Seq)
		return
	}

	if val, ok := a.msgs[aMsg.Seq]; ok {
		// Use the original AuditMessageGroup if we have one
		val.AddMessage(aMsg)
	} else {
		// Create a new AuditMessageGroup
		a.msgs[aMsg.Seq] = NewAuditMessageGroup(aMsg)
	}

	a.flushOld()
}

// Outputs any messages that are old enough
// This is because there is no indication of multi message events coming from kaudit
func (a *AuditMarshaller) flushOld() {
	now := time.Now()
	for seq, msg := range a.msgs {
		if msg.CompleteAfter.Before(now) || now.Equal(msg.CompleteAfter) {
			a.completeMessage(seq)
		}
	}
}

// Write a complete message group to the configured output in json format
func (a *AuditMarshaller) completeMessage(seq int) {
	var msg *AuditMessageGroup
	var ok bool
	var err error

	if msg, ok = a.msgs[seq]; !ok {
		//TODO: attempted to complete a missing message, log?
		return
	}

	a.buf, err = json.Marshal(msg)
	if err != nil {
		log.Fatal(err)
	}

	// Remove the message
	delete(a.msgs, seq)

	a.al.Write(a.buf)
}
