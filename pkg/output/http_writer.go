package output

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/spf13/viper"
)

type HttpWriter struct {
	url      string
	messages chan []byte
	cancel   context.CancelFunc
	client   *http.Client
}

func init() {
	register("http", newHTTPWriter)
}

func httpClient(cert *tls.Certificate, caCertPool *x509.CertPool) *http.Client {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		RootCAs:      caCertPool,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	return &http.Client{Transport: transport}
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

		resp, err := w.client.Do(req.WithContext(ctx))
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
	if serviceURL == "" {
		return nil, fmt.Errorf("Output http URL must be set")
	}

	workerCount := config.GetInt("output.http.worker_count")
	if workerCount < 1 {
		return nil, fmt.Errorf("Output workers for http must be at least 1, %v provided", workerCount)
	}

	clientCertPath := config.GetString("output.http.client_cert")
	clientKeyPath := config.GetString("output.http.client_key")
	cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, err
	}

	var caCerts *x509.CertPool
	if caCertPath := config.GetString("output.http.ca_cert"); caCertPath != "" {
		caCerts = x509.NewCertPool()
		caCert, err := ioutil.ReadFile(caCertPath)
		caCerts.AppendCertsFromPEM(caCert)
		if err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(context.Background())

	writer := &HttpWriter{
		url:      serviceURL,
		messages: make(chan []byte, workerCount),
		cancel:   cancel,
		client:   httpClient(&cert, caCerts),
	}

	for i := 0; i < workerCount; i++ {
		go writer.Process(ctx)
	}

	return NewAuditWriter(writer, attempts), nil
}
