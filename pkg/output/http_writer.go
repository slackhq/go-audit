package output

import (
	"bytes"
	"context"
	"fmt"

	"github.com/spf13/viper"
)

type HttpWriter struct {
	url      string
	messages chan []byte
	cancel   context.CancelFunc
}

func init() {
	register("http", newHTTPWriter)
}

func (w *HttpWriter) Write(p []byte) (n int, err error) {
	bytesSent := len(p)
	select {
	case w.messages <- p:
	default:
	}

	return bytesSent, nil
}

// Process blocks and listens for messages in the channel
func (w *HttpWriter) Process(ctx context.Context) {
	for p := range w.messages {
		payload := bytes.NewReader(p)
		req, err := http.NewRequest(http.MethodPost, w.url, payload)
		// add TLS cert work here
		if err != nil {
			// maybe log if you care
			continue
		}

		resp, err := http.Do(req.WithContext(ctx))
		if err != nil {
			// maybe log if you care
			continue
		}
		resp.Body.Close()
	}
}

func newHTTPWriter(config *viper.Viper) (*AuditWriter, error) {
	attempts := config.GetInt("output.http.attempts")
	if attempts < 1 {
		return nil, fmt.Errorf("Output attempts for http must be at least 1, %v provided", attempts)
	}

	serviceURL := config.GetString("output.http.url")
	if url == "" {
		return nil, fmt.Errorf("Output http URL must be set")
	}

	workerCount := config.GetInt("output.http.worker_count")
	if workerCount < 1 {
		return nil, fmt.Errorf("Output workers for http must be at least 1, %v provided", workerCount)
	}

	ctx, cancel := context.WithCancel(context.Background())

	writer := &HttpWriter{
		url:      serviceURL,
		messages: make(chan []byte, workerCount),
		cancel:   cancel,
	}

	for i := 0; i < workerCount; i++ {
		go writer.Process(ctx)
	}

	return NewAuditWriter(writer, attempts), nil
}
