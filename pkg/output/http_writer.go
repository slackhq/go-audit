package output

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"sync"

	"github.com/pantheon-systems/go-audit/pkg/output/http_transformer"
	"github.com/pantheon-systems/go-audit/pkg/slog"
	"github.com/spf13/viper"
)

// TODO: where do we close the channel, how do we gracefully stop when the cancel has been thrown

// HTTPWriter is the class that encapsulates the http output plugin
type HTTPWriter struct {
	url                     string
	messages                chan *[]byte
	client                  *http.Client
	wg                      *sync.WaitGroup
	ResponseBodyTransformer http_transformer.ResponseBodyTransformer
}

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

			body, err := w.ResponseBodyTransformer.Transform(p)
			if err != nil || body == nil {
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

	var respBodyTransName string
	if config.IsSet("output.http.response_body_transformer") {
		respBodyTransName = config.GetString("output.http.response_body_transformer")
	}

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

	wg := &sync.WaitGroup{}
	wg.Add(workerCount)

	writer := &HTTPWriter{
		url:      serviceURL,
		messages: queue,
		client:   httpClient,
		wg:       wg,
		ResponseBodyTransformer: http_transformer.GetResponseBodyTransformer(respBodyTransName),
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
