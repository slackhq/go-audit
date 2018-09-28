package main

import (
	"github.com/golang/protobuf/proto"
	"os/signal"
	"os"
	"syscall"
	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

const outputChannelSize = 32

type DnsOutput struct {
	outputChannel chan []byte
	wait          chan bool
}

func NewDnsOutput() (o *DnsOutput) {
	o = new(DnsOutput)
	o.outputChannel = make(chan []byte, outputChannelSize)
	o.wait = make(chan bool)
	return
}

func (o *DnsOutput) GetOutputChannel() chan []byte {
	return o.outputChannel
}

func (o *DnsOutput) RunOutputLoop() {
	dt := &dnstap.Dnstap{}
	for frame := range o.outputChannel {
		if err := proto.Unmarshal(frame, dt); err != nil {
			el.Fatalf("dnstap.DnsOutput: proto.Unmarshal() failed: %s\n", err)
			break
		}
		if *dt.Type == dnstap.Dnstap_MESSAGE {
			if dt.Message.ResponseMessage != nil {
				msg := new(dns.Msg)
				err := msg.Unpack(dt.Message.ResponseMessage)
				if err != nil {
					el.Println(err)
				} else {
					for i, rr := range msg.Answer {
						if msg.Answer[i].Header().Rrtype == dns.TypeA {
							el.Println(i, msg.Answer[i].(*dns.A).A.String(), rr.Header().Name)
						}
					}
				}
			}
		}
	}
	close(o.wait)
}

func (o *DnsOutput) Close() {
	close(o.outputChannel)
	<-o.wait
}

func outputOpener() func() dnstap.Output {
	return func() dnstap.Output {
		var o dnstap.Output
		o = NewDnsOutput()
		go o.RunOutputLoop()
		return o
	}
}

func outputLoop(opener func() dnstap.Output, data <-chan []byte, done chan<- struct{}) {
	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt, syscall.SIGHUP)
	o := opener()
	defer func() {
		o.Close()
		close(done)
		os.Exit(0)
	}()
	for {
		select {
		case b, ok := <-data:
			if !ok {
				return
			}
			o.GetOutputChannel() <- b
		case sig := <-sigch:
			if sig == syscall.SIGHUP {
				o.Close()
				o = opener()
				continue
			}
			return
		}
	}
}
