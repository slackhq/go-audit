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
}

func NewAuditMarshaller(al AuditLogger) (*AuditMarshaller){
	return &AuditMarshaller{
		al: al,
		msgs: make(map[int]*AuditMessageGroup, 5), // It is not typical to have more than 2 messages at any given time
	}
}

func (a *AuditMarshaller) Consume(nlMsg *syscall.NetlinkMessage) {
	//TODO: currently message completion requires the canary, make the client shoot noop messages occasionally to flush this
	aMsg := NewAuditMessage(nlMsg)

	// We got an invalid audit message, return the current message and reset
	if aMsg.Seq == 0 {
		a.flushOld()
		return
	}

	// Detect if we lost any messages
	if aMsg.Seq > a.lastSeq + 1 {
		fmt.Println("Likely missed a packet, last seen:", a.lastSeq, "; current:", aMsg.Seq)
	}

	// Keep track of the largest sequence
	if aMsg.Seq > a.lastSeq {
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

func (a *AuditMarshaller) flushOld() {
	now := time.Now()
	for seq, msg := range a.msgs {
		if msg.CompleteAfter.Before(now) || now.Equal(msg.CompleteAfter) {
			a.completeMessage(seq)
		}
	}
}

func (a *AuditMarshaller) completeMessage(seq int) {
	var msg *AuditMessageGroup
	var ok bool

	if msg, ok = a.msgs[seq]; !ok {
		//TODO: attempted to complete a missing message, log?
		return
	}

	s, err := json.Marshal(msg)
	if err != nil {
		log.Fatal(err)
	}

	// Remove the message
	delete(a.msgs, seq)

	a.al.Write(s)
}
