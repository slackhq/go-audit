package output

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/pantheon-systems/go-audit/pkg/slog"
	"github.com/spf13/viper"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sync"
)

// TODO: where do we close the channel, how do we gracefully stop when the cancel has been thrown

// HTTPWriter is the class that encapsulates the http output plugin
type HTTPWriter struct {
	url                    string
	messages               chan *[]byte
	client                 *http.Client
	hostname               string
	wg                     *sync.WaitGroup
	responseBodyTranformer func(*[]byte) *[]byte
}

type notification struct {
	Topic      string            `json:"topic"`
	Attributes map[string]string `json:"attributes"`
	Data       string            `json:"data"`
	Version    string            `json:"version"`
}

var ruleKeyRegex = regexp.MustCompile(`"rule_key":"(.*)"`)

func init() {
	register("http", newHTTPWriter)
}

func (w *HTTPWriter) Write(p []byte) (n int, err error) {
	// this defered method catches the panic on write to the channel
	// then handles shutdown gracefully
	defer func() {
		if r := recover(); r != nil {
			_, ok := r.(error)
			if !ok {
				slog.Error.Printf("pkg: %v", r)
			}
			slog.Info.Print("Waiting for goroutines to complete")
			w.wg.Wait()
			slog.Info.Print("Goroutines completed")
			os.Exit(0)
		}
	}()

	bytesSent := len(p)
	select {
	case w.messages <- &p:
	default:
		slog.Error.Printf("Buffer full or closed, messages dropped")
	}

	return bytesSent, nil
}

// Process blocks and listens for messages in the channel
func (w *HTTPWriter) Process(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			w.wg.Done()
			return
		case p := <-w.messages:
			if p == nil {
				continue
			}

			body := w.responseBodyTranformer(p)
			if body == nil {
				continue
			}
			payloadReader := bytes.NewReader(*body)

			req, err := http.NewRequest(http.MethodPost, w.url, payloadReader)
			if err != nil {
				slog.Error.Printf("HTTPWriter.Process could not create new request: %s", err.Error())
				continue
			}

			resp, err := w.client.Do(req.WithContext(ctx))
			if err != nil {
				slog.Error.Printf("HTTPWriter.Process could not send request: %s", err.Error())
				continue
			}
			resp.Body.Close()
		}
	}
}

func newHTTPWriter(config *viper.Viper) (*AuditWriter, error) {
	var err error

	attempts := config.GetInt("output.http.attempts")
	if attempts < 1 {
		return nil, fmt.Errorf("Output attempts for http must be at least 1, %v provided", attempts)
	}

	serviceURL := config.GetString("output.http.url")
	workerCount := config.GetInt("output.http.worker_count")
	bufferSize := config.GetInt("output.http.buffer_size")

	var httpClient = &http.Client{}
	if config.IsSet("output.http.ssl") && config.GetBool("output.http.ssl") {
		clientCertPath := config.GetString("output.http.client_cert")
		clientKeyPath := config.GetString("output.http.client_key")
		caCertPath := config.GetString("output.http.ca_cert")
		httpClient, err = createSSLClient(clientCertPath, clientKeyPath, caCertPath)
		if err != nil {
			return nil, err
		}
	}

	writer, err := createHTTPWriter(httpClient, bufferSize, workerCount, serviceURL)
	if err != nil {
		return nil, err
	}
	return NewAuditWriter(writer, attempts), nil
}

func createHTTPWriter(httpClient *http.Client, bufferSize, workerCount int, serviceURL string) (*HTTPWriter, error) {
	if serviceURL == "" {
		return nil, fmt.Errorf("Output http URL must be set")
	}

	if workerCount < 1 {
		return nil, fmt.Errorf("Output workers for http must be at least 1, %v provided", workerCount)
	}

	if bufferSize < workerCount {
		return nil, fmt.Errorf("Buffer size must be larger than worker count, %v provided", bufferSize)
	}

	queue := make(chan *[]byte, bufferSize)

	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	go func() {
		select {
		case <-signals:
			close(queue)
			cancel()
		case <-ctx.Done():
		}
	}()

	host, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	wg := &sync.WaitGroup{}
	wg.Add(workerCount)

	writer := &HTTPWriter{
		url:      serviceURL,
		messages: queue,
		client:   httpClient,
		hostname: host,
		wg:       wg,
		responseBodyTranformer: func(auditMessage *[]byte) *[]byte {
			// The default responseBodyTranformer does nothing (noop)
			return auditMessage
		},
	}

	for i := 0; i < workerCount; i++ {
		go writer.Process(ctx)
	}

	return writer, nil
}

func sslHTTPClient(cert *tls.Certificate, caCertPool *x509.CertPool) *http.Client {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		RootCAs:      caCertPool,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	return &http.Client{Transport: transport}
}

func createSSLClient(clientCertPath, clientKeyPath, caCertPath string) (*http.Client, error) {
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

	return sslHTTPClient(&cert, caCerts), nil
}
