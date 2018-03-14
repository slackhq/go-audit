package output

import (
	"encoding/json"
	"io"
	"time"

	"github.com/pantheon-systems/go-audit/pkg/parser"
	"github.com/pantheon-systems/go-audit/pkg/slog"
)

type AuditWriter struct {
	e        *json.Encoder
	w        io.Writer
	attempts int
}

func NewAuditWriter(w io.Writer, attempts int) *AuditWriter {
	return &AuditWriter{
		e:        json.NewEncoder(w),
		w:        w,
		attempts: attempts,
	}
}

func (a *AuditWriter) Write(msg *parser.AuditMessageGroup) (err error) {
	for i := 0; i < a.attempts; i++ {
		err = a.e.Encode(msg)
		if err == nil {
			break
		}

		if i != a.attempts {
			// We have to reset the encoder because write errors are kept internally and can not be retried
			a.e = json.NewEncoder(a.w)
			slog.Error.Println("Failed to write message, retrying in 1 second. Error:", err)
			time.Sleep(time.Second * 1)
		}
	}

	return err
}
