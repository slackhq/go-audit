package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type AuditWriter struct {
	e        *json.Encoder
	w        io.Writer
	attempts int
	mutex    sync.RWMutex
}

func NewAuditWriter(w io.Writer, attempts int) *AuditWriter {
	return &AuditWriter{
		e:        json.NewEncoder(w),
		w:        w,
		attempts: attempts,
	}
}

func (a *AuditWriter) Write(msg *AuditMessageGroup) (err error) {
	a.mutex.RLock()
	for i := 0; i < a.attempts; i++ {
		err = a.e.Encode(msg)
		if err == nil {
			break
		}

		if i != a.attempts {
			// We have to reset the encoder because write errors are kept internally and can not be retried
			a.e = json.NewEncoder(a.w)
			el.Println("Failed to write message, retrying in 1 second. Error:", err)
			time.Sleep(time.Second * 1)
		}
	}
	a.mutex.RUnlock()

	return err
}

func (self *AuditWriter) rotate(ow *AuditWriter) error {
	oldFile := self.w.(*os.File)

	self.mutex.Lock()
	self.w = ow.w
	self.e = ow.e
	self.mutex.Unlock()

	err := oldFile.Close()
	if err != nil {
		return fmt.Errorf("Error re-opening log file. Exiting.")
	}

	return nil
}
