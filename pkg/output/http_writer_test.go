package output

import (
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func Test_newHttpWriter(t *testing.T) {
	// attempts error
	c := viper.New()
	c.Set("output.http.attempts", 0)
	w, err := newHttpWriter(c)
	assert.EqualError(t, err, "Output attempts for http must be at least 1, 0 provided")
	assert.Nil(t, w)

	// url error
	c := viper.New()
	c.Set("output.http.url", "")
	c.Set("output.http.attempts", 1)
	w, err := newHttpWriter(c)
	assert.EqualError(t, err, "Output http URL must be set")
	assert.Nil(t, w)

	// All good
	c = viper.New()
	c.Set("output.http.url", "http://someurl.com")
	c.Set("output.http.attempts", 1)
	w, err = newHttpWriter(c)
	assert.Nil(t, err)
	assert.NotNil(t, w)
	assert.IsType(t, &os.File{}, w.w)
}
