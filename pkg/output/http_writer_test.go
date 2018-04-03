package output

import (
	"context"
	"io/ioutil"
	"net/http"
	"sync"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestHTTPWriter_newHttpWriter(t *testing.T) {
	// attempts error
	c := viper.New()
	c.Set("output.http.attempts", 0)
	w, err := newHTTPWriter(c)
	assert.EqualError(t, err, "Output attempts for http must be at least 1, 0 provided")
	assert.Nil(t, w)

	// url error
	c = viper.New()
	c.Set("output.http.url", "")
	c.Set("output.http.attempts", 1)
	w, err = newHTTPWriter(c)
	assert.EqualError(t, err, "Output http URL must be set")
	assert.Nil(t, w)

	// worker count error
	c = viper.New()
	c.Set("output.http.url", "http://someurl.com")
	c.Set("output.http.attempts", 1)
	c.Set("output.http.worker_count", 0)
	w, err = newHTTPWriter(c)
	assert.EqualError(t, err, "Output workers for http must be at least 1, 0 provided")
	assert.Nil(t, w)

	// All good no ssl
	c = viper.New()
	c.Set("output.http.url", "http://someurl.com")
	c.Set("output.http.attempts", 1)
	c.Set("output.http.worker_count", 2)
	c.Set("output.http.ssl", false)
	w, err = newHTTPWriter(c)
	assert.Nil(t, err)
	assert.NotNil(t, w)
	assert.IsType(t, &HTTPWriter{}, w.w)

	// All good no ssl (dont set)
	c = viper.New()
	c.Set("output.http.url", "http://someurl.com")
	c.Set("output.http.attempts", 1)
	c.Set("output.http.worker_count", 2)
	w, err = newHTTPWriter(c)
	assert.Nil(t, err)
	assert.NotNil(t, w)
	assert.IsType(t, &HTTPWriter{}, w.w)
	assert.Equal(t, 1, w.attempts)

	// ssl no certs error
	c = viper.New()
	c.Set("output.http.url", "http://someurl.com")
	c.Set("output.http.attempts", 1)
	c.Set("output.http.worker_count", 2)
	c.Set("output.http.ssl", true)
	w, err = newHTTPWriter(c)
	assert.EqualError(t, err, "SSL is enabled, please specify the required certificates (client_cert, client_key, ca_cert)")
	assert.Nil(t, w)
}

func TestHTTPWriter_write(t *testing.T) {
	msgChannel := make(chan []byte, 1)
	writer := &HTTPWriter{
		messages: msgChannel,
	}

	msg := []byte("test string")
	result, err := writer.Write(msg)
	assert.Nil(t, err)
	assert.Equal(t, len(msg), result)

	resultMsg := <-msgChannel
	assert.Equal(t, "test string", string(resultMsg))
}

func TestHTTPWriter_process(t *testing.T) {
	receivedPost := false
	var body []byte
	var byteCount int64

	wg := &sync.WaitGroup{}
	wg.Add(1)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		receivedPost = true
		body, _ = ioutil.ReadAll(r.Body)
		byteCount = r.ContentLength
		wg.Done()
	})
	go func() {
		http.ListenAndServe(":8888", nil)
	}()

	msgChannel := make(chan []byte, 1)
	msg := []byte("test string")
	writer := &HTTPWriter{
		url:      "http://localhost:8888",
		client:   &http.Client{},
		messages: msgChannel,
	}

	msgChannel <- msg
	go writer.Process(context.Background())

	wg.Wait()

	assert.True(t, receivedPost)
	assert.Equal(t, int64(11), byteCount)
	assert.Equal(t, msg, body)
}
