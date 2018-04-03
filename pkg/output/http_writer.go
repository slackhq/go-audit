package output

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/prometheus/common/log"
	"github.com/spf13/viper"
)

// TODO: where do we close the channel, how do we gracefully stop when the cancel has been thrown

// HTTPWriter is the class that encapsulates the http output plugin
type HTTPWriter struct {
	url      string
	messages chan []byte
	cancel   context.CancelFunc
	client   *http.Client
}

func init() {
	register("http", newHTTPWriter)
}

func (w *HTTPWriter) Write(p []byte) (n int, err error) {
	bytesSent := len(p)
	select {
	case w.messages <- p:
	default:
	}

	return bytesSent, nil
}

// Process blocks and listens for messages in the channel
func (w *HTTPWriter) Process(ctx context.Context) {
	for p := range w.messages {
		payload := bytes.NewReader(p)
		req, err := http.NewRequest(http.MethodPost, w.url, payload)
		if err != nil {
			log.Errorf("HTTPWriter.Process could not create new request: %s", err.Error())
			continue
		}

		resp, err := w.client.Do(req.WithContext(ctx))
		if err != nil {
			log.Errorf("HTTPWriter.Process could not send request: %s", err.Error())
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

	var httpClient = &http.Client{}
	if config.IsSet("output.http.ssl") && config.GetBool("output.http.ssl") {
		clientCertPath := config.GetString("output.http.client_cert")
		clientKeyPath := config.GetString("output.http.client_key")
		caCertPath := config.GetString("output.http.ca_cert")
		if clientCertPath == "" || clientKeyPath == "" || caCertPath == "" {
			return nil, fmt.Errorf("SSL is enabled, please specify the required certificates (client_cert, client_key, ca_cert)")
		}

		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return nil, err
		}

		var caCerts *x509.CertPool
		caCerts = x509.NewCertPool()
		caCert, err := ioutil.ReadFile(caCertPath)
		caCerts.AppendCertsFromPEM(caCert)
		if err != nil {
			return nil, err
		}
		httpClient = sslHTTPClient(&cert, caCerts)
	}

	ctx, cancel := context.WithCancel(context.Background())

	writer := &HTTPWriter{
		url:      serviceURL,
		messages: make(chan []byte, workerCount),
		cancel:   cancel,
		client:   httpClient,
	}

	for i := 0; i < workerCount; i++ {
		go writer.Process(ctx)
	}

	return NewAuditWriter(writer, attempts), nil
}

func sslHTTPClient(cert *tls.Certificate, caCertPool *x509.CertPool) *http.Client {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		RootCAs:      caCertPool,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	return &http.Client{Transport: transport}
}
