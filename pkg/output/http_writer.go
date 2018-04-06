package output

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sync"

	"github.com/prometheus/common/log"
	"github.com/spf13/viper"
)

// TODO: where do we close the channel, how do we gracefully stop when the cancel has been thrown

// HTTPWriter is the class that encapsulates the http output plugin
type HTTPWriter struct {
	url      string
	messages chan *[]byte
	client   *http.Client
	hostname string
	wg       *sync.WaitGroup
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
				log.Errorf("pkg: %v", r)
			}
			log.Info("Waiting for goroutines to complete")
			w.wg.Wait()
			log.Info("Goroutines completed")
			os.Exit(0)
		}
	}()

	bytesSent := len(p)
	select {
	case w.messages <- &p:
	default:
		log.Error("Buffer full or closed, messages dropped")
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

			body := w.buildAPIObject(p)
			if body == nil {
				continue
			}
			payloadReader := bytes.NewReader(*body)

			req, err := http.NewRequest(http.MethodPost, w.url, payloadReader)
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
}

func (w *HTTPWriter) buildAPIObject(auditMessage *[]byte) *[]byte {
	matches := ruleKeyRegex.FindStringSubmatch(string(*auditMessage))
	if len(matches) < 2 || matches[1] == "" {
		return nil
	}

	notif := notification{
		Topic: matches[1],
		Data:  string(*auditMessage),
		Attributes: map[string]string{
			"hostname": w.hostname,
		},
		Version: "1.0.0",
	}

	body, err := json.Marshal(notif)
	if err != nil {
		return nil
	}

	return &body
}

func newHTTPWriter(config *viper.Viper) (*AuditWriter, error) {
	var err error

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

	bufferSize := config.GetInt("output.http.buffer_size")
	if bufferSize < workerCount {
		return nil, fmt.Errorf("Buffer size must be larger than worker count, %v provided", bufferSize)
	}

	var httpClient = &http.Client{}
	if config.IsSet("output.http.ssl") && config.GetBool("output.http.ssl") {
		clientCertPath := config.GetString("output.http.client_cert")
		clientKeyPath := config.GetString("output.http.client_key")
		caCertPath := config.GetString("output.http.ca_cert")
		if clientCertPath == "" || clientKeyPath == "" || caCertPath == "" {
			return nil, fmt.Errorf("SSL is enabled, please specify the required certificates (client_cert, client_key, ca_cert)")
		}
		httpClient, err = createSSLClient(clientCertPath, clientKeyPath, caCertPath)
		if err != nil {
			return nil, err
		}
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

func createSSLClient(clientCertPath, clientKeyPath, caCertPath string) (*http.Client, error) {
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
