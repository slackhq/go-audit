package output

import (
	"log/syslog"
	"net"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func Test_newSyslogWriter(t *testing.T) {
	// attempts error
	c := viper.New()
	c.Set("output.syslog.attempts", 0)
	w, err := newSyslogWriter(c)
	assert.EqualError(t, err, "Output attempts for syslog must be at least 1, 0 provided")
	assert.Nil(t, w)

	// dial error
	c = viper.New()
	c.Set("output.syslog.attempts", 1)
	c.Set("output.syslog.priority", -1)
	w, err = newSyslogWriter(c)
	assert.EqualError(t, err, "Failed to open syslog writer. Error: log/syslog: invalid priority")
	assert.Nil(t, w)

	// All good
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}

	defer l.Close()

	c = viper.New()
	c.Set("output.syslog.attempts", 1)
	c.Set("output.syslog.network", "tcp")
	c.Set("output.syslog.address", l.Addr().String())
	w, err = newSyslogWriter(c)
	assert.Nil(t, err)
	assert.NotNil(t, w)
	assert.IsType(t, &syslog.Writer{}, w.w)
}
