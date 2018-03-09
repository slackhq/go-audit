package output

import (
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func Test_newStdOutWriter(t *testing.T) {
	// attempts error
	c := viper.New()
	c.Set("output.stdout.attempts", 0)
	w, err := newStdOutWriter(c)
	assert.EqualError(t, err, "Output attempts for stdout must be at least 1, 0 provided")
	assert.Nil(t, w)

	// All good
	c = viper.New()
	c.Set("output.stdout.attempts", 1)
	w, err = newStdOutWriter(c)
	assert.Nil(t, err)
	assert.NotNil(t, w)
	assert.IsType(t, &os.File{}, w.w)
}
