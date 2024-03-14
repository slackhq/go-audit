package main

import (
	"compress/flate"
	"errors"
	"log/syslog"
	"net"
	"os"
	"os/user"
	"path"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"gopkg.in/Graylog2/go-gelf.v2/gelf"
)

func Test_loadConfig(t *testing.T) {
	file := createTempFile(t, "defaultValues.test.yaml", "")
	defer os.Remove(file)

	// defaults
	config, err := loadConfig(file)
	assert.Equal(t, 1300, config.GetInt("events.min"), "events.min should default to 1300")
	assert.Equal(t, 1399, config.GetInt("events.max"), "events.max should default to 1399")
	assert.Equal(t, true, config.GetBool("message_tracking.enabled"), "message_tracking.enabled should default to true")
	assert.Equal(t, false, config.GetBool("message_tracking.log_out_of_order"), "message_tracking.log_out_of_order should default to false")
	assert.Equal(t, 500, config.GetInt("message_tracking.max_out_of_order"), "message_tracking.max_out_of_order should default to 500")
	assert.Equal(t, false, config.GetBool("output.syslog.enabled"), "output.syslog.enabled should default to false")
	assert.Equal(t, 132, config.GetInt("output.syslog.priority"), "output.syslog.priority should default to 132")
	assert.Equal(t, "go-audit", config.GetString("output.syslog.tag"), "output.syslog.tag should default to go-audit")
	assert.Equal(t, 3, config.GetInt("output.syslog.attempts"), "output.syslog.attempts should default to 3")
	assert.Equal(t, false, config.GetBool("output.gelf.enabled"), "output.gelf.enabled should default to false")
	assert.Equal(t, 3, config.GetInt("output.gelf.attempts"), "output.gelf.attempts should default to 3")
	assert.Equal(t, "udp", config.GetString("output.gelf.network"), "output.gelf.network should default to udp")
	assert.Equal(t, int(flate.BestSpeed), config.GetInt("output.gelf.compression.level"), "output.gelf.compression.level should default to flate.BestSpeed")
	assert.Equal(t, int(gelf.CompressGzip), config.GetInt("output.gelf.compression.type"), "output.gelf.compression.type should default to gelf.CompressGzip")
	assert.Equal(t, 0, config.GetInt("log.flags"), "log.flags should default to 0")
	assert.Equal(t, 0, l.Flags(), "stdout log flags was wrong")
	assert.Equal(t, 0, el.Flags(), "stderr log flags was wrong")
	assert.Nil(t, err)

	// parse error
	file = createTempFile(t, "defaultValues.test.yaml", "this is bad")
	config, err = loadConfig(file)
	assert.EqualError(t, err, "While parsing config: yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `this is...` into map[string]interface {}")
	assert.Nil(t, config)
}

func Test_setRules(t *testing.T) {
	defer resetLogger()

	// fail to flush rules
	config := viper.New()

	err := setRules(config, func(s string, a ...string) error {
		if s == "auditctl" && a[0] == "-D" {
			return errors.New("testing")
		}

		return nil
	})

	assert.EqualError(t, err, "Failed to flush existing audit rules. Error: testing")

	// fail on 0 rules
	err = setRules(config, func(s string, a ...string) error { return nil })
	assert.EqualError(t, err, "No audit rules found")

	// failure to set rule
	r := 0
	config.Set("rules", []string{"-a -1 -2", "", "-a -3 -4"})
	err = setRules(config, func(s string, a ...string) error {
		if a[0] != "-D" {
			return errors.New("testing rule")
		}

		r++

		return nil
	})

	assert.Equal(t, 1, r, "Wrong number of rule set attempts")
	assert.EqualError(t, err, "Failed to add rule #1. Error: testing rule")

	// properly set rules
	r = 0
	err = setRules(config, func(s string, a ...string) error {
		// Skip the flush rules
		if a[0] != "-a" {
			return nil
		}

		if (a[1] == "-1" && a[2] == "-2") || (a[1] == "-3" && a[2] == "-4") {
			r++
		}

		return nil
	})

	assert.Equal(t, 2, r, "Wrong number of correct rule set attempts")
	assert.Nil(t, err)
}

func Test_createFileOutput(t *testing.T) {
	// attempts error
	c := viper.New()
	c.Set("output.file.attempts", 0)
	w, err := createFileOutput(c)
	assert.EqualError(t, err, "Output attempts for file must be at least 1, 0 provided")
	assert.Nil(t, w)

	// failure to create/open file
	c = viper.New()
	c.Set("output.file.attempts", 1)
	c.Set("output.file.path", "/do/not/exist/please")
	c.Set("output.file.mode", 0644)
	w, err = createFileOutput(c)
	assert.EqualError(t, err, "Failed to open output file. Error: open /do/not/exist/please: no such file or directory")
	assert.Nil(t, w)

	// chmod error
	c = viper.New()
	c.Set("output.file.attempts", 1)
	c.Set("output.file.path", path.Join(os.TempDir(), "go-audit.test.log"))
	w, err = createFileOutput(c)
	assert.EqualError(t, err, "Output file mode should be greater than 0000")
	assert.Nil(t, w)

	// uid error
	c = viper.New()
	c.Set("output.file.attempts", 1)
	c.Set("output.file.path", path.Join(os.TempDir(), "go-audit.test.log"))
	c.Set("output.file.mode", 0644)
	w, err = createFileOutput(c)
	assert.EqualError(t, err, "Could not find uid for user . Error: user: unknown user ")
	assert.Nil(t, w)

	uid := os.Getuid()
	gid := os.Getgid()
	u, _ := user.LookupId(strconv.Itoa(uid))
	g, _ := user.LookupGroupId(strconv.Itoa(gid))

	// travis-ci is silly
	if u.Username == "" {
		u.Username = g.Name
	}

	// gid error
	c = viper.New()
	c.Set("output.file.attempts", 1)
	c.Set("output.file.path", path.Join(os.TempDir(), "go-audit.test.log"))
	c.Set("output.file.mode", 0644)
	c.Set("output.file.user", u.Username)
	w, err = createFileOutput(c)
	assert.EqualError(t, err, "Could not find gid for group . Error: group: unknown group ")
	assert.Nil(t, w)

	// chown error
	c = viper.New()
	c.Set("output.file.attempts", 1)
	c.Set("output.file.path", path.Join(os.TempDir(), "go-audit.test.log"))
	c.Set("output.file.mode", 0644)
	c.Set("output.file.user", "root")
	c.Set("output.file.group", "root")
	w, err = createFileOutput(c)
	assert.EqualError(t, err, "Could not chown output file. Error: chown /tmp/go-audit.test.log: operation not permitted")
	assert.Nil(t, w)

	// All good
	c = viper.New()
	c.Set("output.file.attempts", 1)
	c.Set("output.file.path", path.Join(os.TempDir(), "go-audit.test.log"))
	c.Set("output.file.mode", 0644)
	c.Set("output.file.user", u.Username)
	c.Set("output.file.group", g.Name)
	w, err = createFileOutput(c)
	assert.Nil(t, err)
	assert.NotNil(t, w)
	assert.IsType(t, &os.File{}, w.w)
}

func Test_createSyslogOutput(t *testing.T) {
	// attempts error
	c := viper.New()
	c.Set("output.syslog.attempts", 0)
	w, err := createSyslogOutput(c)
	assert.EqualError(t, err, "Output attempts for syslog must be at least 1, 0 provided")
	assert.Nil(t, w)

	// dial error
	c = viper.New()
	c.Set("output.syslog.attempts", 1)
	c.Set("output.syslog.priority", -1)
	w, err = createSyslogOutput(c)
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
	w, err = createSyslogOutput(c)
	assert.Nil(t, err)
	assert.NotNil(t, w)
	assert.IsType(t, &syslog.Writer{}, w.w)
}

func Test_createStdOutOutput(t *testing.T) {
	// attempts error
	c := viper.New()
	c.Set("output.stdout.attempts", 0)
	w, err := createStdOutOutput(c)
	assert.EqualError(t, err, "Output attempts for stdout must be at least 1, 0 provided")
	assert.Nil(t, w)

	// All good
	c = viper.New()
	c.Set("output.stdout.attempts", 1)
	w, err = createStdOutOutput(c)
	assert.Nil(t, err)
	assert.NotNil(t, w)
	assert.IsType(t, &os.File{}, w.w)
}

func Test_createGELFOutput(t *testing.T) {
	t.Run("When attempts is less than one, should retun an expected error", func(t *testing.T) {
		c := viper.New()
		c.Set("output.gelf.attempts", 0)
		w, err := createGELFOutput(c)
		assert.EqualError(t, err, "Output attempts for GELF must be at least 1, 0 provided")
		assert.Nil(t, w)
	})

	t.Run("When address is not set, should return an expected error", func(t *testing.T) {
		c := viper.New()
		c.Set("output.gelf.attempts", 3)
		w, err := createGELFOutput(c)
		assert.EqualError(t, err, "Output address for GELF must be set")
		assert.Nil(t, w)
	})

	t.Run("When using UDP network, should return a gelf.UDPWriter writer", func(t *testing.T) {
		l, err := net.ListenUDP("udp", &net.UDPAddr{})
		if err != nil {
			t.Fatal(err)
		}

		defer l.Close()

		c := viper.New()
		c.Set("output.gelf.attempts", 3)
		c.Set("output.gelf.network", "udp")
		c.Set("output.gelf.address", l.LocalAddr().String())
		writer, err := createGELFOutput(c)
		assert.Nil(t, err)
		assert.IsType(t, &gelf.UDPWriter{}, writer.w)
	})

	t.Run("When using TCP network, should return a gelf.TCPWriter writer", func(t *testing.T) {
		l, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Fatal(err)
		}

		defer l.Close()

		c := viper.New()
		c.Set("output.gelf.attempts", 3)
		c.Set("output.gelf.network", "tcp")
		c.Set("output.gelf.address", l.Addr().String())
		writer, err := createGELFOutput(c)
		assert.Nil(t, err)
		assert.Equal(t, writer.attempts, 3)
		assert.IsType(t, &gelf.TCPWriter{}, writer.w)
	})

	t.Run("When using an unsupported network (not UDP or TCP), should return an expected error", func(t *testing.T) {
		c := viper.New()
		c.Set("output.gelf.attempts", 3)
		c.Set("output.gelf.address", "/var/run/gelf.sock")

		unsupportedNetworks := []string{"unix", "unixgram", "unixpacket"}

		for _, network := range unsupportedNetworks {
			c.Set("output.gelf.network", network)
			_, err := createGELFOutput(c)
			assert.EqualError(t, err, "unsupported network by GELF library")
		}
	})

	t.Run("When using a custom compreession settings, should return a gelf.UPDWriter with expected compression value", func(t *testing.T) {
		c := viper.New()
		c.Set("output.gelf.attempts", 3)
		c.Set("output.gelf.network", "udp")
		c.Set("output.gelf.address", "localhost:12201")
		c.Set("output.gelf.compression.level", int(flate.BestCompression))
		c.Set("output.gelf.compression.type", int(gelf.CompressZlib))

		w, err := createGELFOutput(c)
		assert.Nil(t, err)

		udpWriter, ok := w.w.(*gelf.UDPWriter)
		assert.True(t, ok)
		assert.Equal(t, udpWriter.CompressionLevel, flate.BestCompression)
		assert.Equal(t, udpWriter.CompressionType, gelf.CompressZlib)
	})
}

func Test_createOutput(t *testing.T) {
	// no outputs
	c := viper.New()
	w, err := createOutput(c)
	assert.EqualError(t, err, "No outputs were configured")
	assert.Nil(t, w)

	// multiple outputs
	uid := os.Getuid()
	gid := os.Getgid()
	u, _ := user.LookupId(strconv.Itoa(uid))
	g, _ := user.LookupGroupId(strconv.Itoa(gid))

	// travis-ci is silly
	if u.Username == "" {
		u.Username = g.Name
	}

	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}

	defer l.Close()

	c = viper.New()
	c.Set("output.syslog.enabled", true)
	c.Set("output.syslog.attempts", 1)
	c.Set("output.syslog.network", "tcp")
	c.Set("output.syslog.address", l.Addr().String())

	c.Set("output.file.enabled", true)
	c.Set("output.file.attempts", 1)
	c.Set("output.file.path", path.Join(os.TempDir(), "go-audit.test.log"))
	c.Set("output.file.mode", 0644)
	c.Set("output.file.user", u.Username)
	c.Set("output.file.group", g.Name)

	w, err = createOutput(c)
	assert.EqualError(t, err, "Only one output can be enabled at a time")
	assert.Nil(t, w)

	// syslog error
	c = viper.New()
	c.Set("output.syslog.enabled", true)
	c.Set("output.syslog.attempts", 0)
	w, err = createOutput(c)
	assert.EqualError(t, err, "Output attempts for syslog must be at least 1, 0 provided")
	assert.Nil(t, w)

	// file error
	c = viper.New()
	c.Set("output.file.enabled", true)
	c.Set("output.file.attempts", 0)
	w, err = createOutput(c)
	assert.EqualError(t, err, "Output attempts for file must be at least 1, 0 provided")
	assert.Nil(t, w)

	// stdout error
	c = viper.New()
	c.Set("output.stdout.enabled", true)
	c.Set("output.stdout.attempts", 0)
	w, err = createOutput(c)
	assert.EqualError(t, err, "Output attempts for stdout must be at least 1, 0 provided")
	assert.Nil(t, w)

	// All good syslog
	c = viper.New()
	c.Set("output.syslog.attempts", 1)
	c.Set("output.syslog.network", "tcp")
	c.Set("output.syslog.address", l.Addr().String())
	w, err = createSyslogOutput(c)
	assert.Nil(t, err)
	assert.NotNil(t, w)
	assert.IsType(t, &syslog.Writer{}, w.w)

	// All good file
	c = viper.New()
	c.Set("output.file.enabled", true)
	c.Set("output.file.attempts", 1)
	c.Set("output.file.path", path.Join(os.TempDir(), "go-audit.test.log"))
	c.Set("output.file.mode", 0644)
	c.Set("output.file.user", u.Username)
	c.Set("output.file.group", g.Name)
	w, err = createOutput(c)
	assert.Nil(t, err)
	assert.NotNil(t, w)
	assert.IsType(t, &AuditWriter{}, w)
	assert.IsType(t, &os.File{}, w.w)

	// File rotation
	os.Rename(path.Join(os.TempDir(), "go-audit.test.log"), path.Join(os.TempDir(), "go-audit.test.log.rotated"))
	_, err = os.Stat(path.Join(os.TempDir(), "go-audit.test.log"))
	assert.True(t, os.IsNotExist(err))
	syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)
	time.Sleep(100 * time.Millisecond)
	_, err = os.Stat(path.Join(os.TempDir(), "go-audit.test.log"))
	assert.Nil(t, err)
}

func Test_createFilters(t *testing.T) {
	lb, elb := hookLogger()
	defer resetLogger()

	// no filters
	c := viper.New()
	f, err := createFilters(c)
	assert.Nil(t, err)
	assert.Empty(t, f)

	// Bad outer filter value
	c = viper.New()
	c.Set("filters", 1)
	f, err = createFilters(c)
	assert.EqualError(t, err, "Could not parse filters object")
	assert.Empty(t, f)

	// Bad inner filter value
	c = viper.New()
	rf := make([]interface{}, 0)
	rf = append(rf, "bad filter definition")
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.EqualError(t, err, "Could not parse filter 1; 'bad filter definition'")
	assert.Empty(t, f)

	// Bad message type - string
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"message_type": "bad message type"})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.EqualError(t, err, "`message_type` in filter 1 could not be parsed; Value: `bad message type`; Error: strconv.ParseUint: parsing \"bad message type\": invalid syntax")
	assert.Empty(t, f)

	// Bad message type - unknown
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"message_type": false})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.EqualError(t, err, "`message_type` in filter 1 could not be parsed; Value: `false`")
	assert.Empty(t, f)

	// Bad regex - not string
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"regex": false})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.EqualError(t, err, "`regex` in filter 1 could not be parsed; Value: `false`")
	assert.Empty(t, f)

	// Bad regex - un-parse-able
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"regex": "["})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.EqualError(t, err, "`regex` in filter 1 could not be parsed; Value: `[`; Error: error parsing regexp: missing closing ]: `[`")
	assert.Empty(t, f)

	// Bad syscall - not string or int
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"syscall": []string{}})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.EqualError(t, err, "`syscall` in filter 1 could not be parsed; Value: `[]`")
	assert.Empty(t, f)

	// Missing regex
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"syscall": "1", "message_type": "1"})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.EqualError(t, err, "Filter 1 is missing the `regex` entry")
	assert.Empty(t, f)

	// Missing message_type
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"syscall": "1", "regex": "1"})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.EqualError(t, err, "Filter 1 is missing the `message_type` entry")
	assert.Empty(t, f)

	// Good with strings
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"message_type": "1", "regex": "1", "syscall": "1"})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.Nil(t, err)
	assert.NotEmpty(t, f)
	assert.Equal(t, "1", f[0].syscall)
	assert.Equal(t, uint16(1), f[0].messageType)
	assert.Equal(t, "1", f[0].regex.String())
	assert.Empty(t, elb.String())
	assert.Equal(t, "Ignoring syscall `1` containing message type `1` matching string `1`\n", lb.String())

	// Good with ints
	lb.Reset()
	elb.Reset()
	c = viper.New()
	rf = make([]interface{}, 0)
	rf = append(rf, map[string]interface{}{"message_type": 1, "regex": "1", "syscall": 1})
	c.Set("filters", rf)
	f, err = createFilters(c)
	assert.Nil(t, err)
	assert.NotEmpty(t, f)
	assert.Equal(t, "1", f[0].syscall)
	assert.Equal(t, uint16(1), f[0].messageType)
	assert.Equal(t, "1", f[0].regex.String())
	assert.Empty(t, elb.String())
	assert.Equal(t, "Ignoring syscall `1` containing message type `1` matching string `1`\n", lb.String())
}

func Benchmark_MultiPacketMessage(b *testing.B) {
	marshaller := NewAuditMarshaller(NewAuditWriter(&noopWriter{}, 1), uint16(1300), uint16(1399), false, false, 1, []AuditFilter{}, nil)

	data := make([][]byte, 6)

	//&{1300,,arch=c000003e,syscall=59,success=yes,exit=0,a0=cc4e68,a1=d10bc8,a2=c69808,a3=7fff2a700900,items=2,ppid=11552,pid=11623,auid=1000,uid=1000,gid=1000,euid=1000,suid=1000,fsuid=1000,egid=1000,sgid=1000,fsgid=1000,tty=pts0,ses=35,comm="ls",exe="/bin/ls",key=(null),1222763,1459376866.885}
	data[0] = []byte{34, 1, 0, 0, 20, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 117, 100, 105, 116, 40, 49, 52, 53, 57, 51, 55, 54, 56, 54, 54, 46, 56, 56, 53, 58, 49, 50, 50, 50, 55, 54, 51, 41, 58, 32, 97, 114, 99, 104, 61, 99, 48, 48, 48, 48, 48, 51, 101, 32, 115, 121, 115, 99, 97, 108, 108, 61, 53, 57, 32, 115, 117, 99, 99, 101, 115, 115, 61, 121, 101, 115, 32, 101, 120, 105, 116, 61, 48, 32, 97, 48, 61, 99, 99, 52, 101, 54, 56, 32, 97, 49, 61, 100, 49, 48, 98, 99, 56, 32, 97, 50, 61, 99, 54, 57, 56, 48, 56, 32, 97, 51, 61, 55, 102, 102, 102, 50, 97, 55, 48, 48, 57, 48, 48, 32, 105, 116, 101, 109, 115, 61, 50, 32, 112, 112, 105, 100, 61, 49, 49, 53, 53, 50, 32, 112, 105, 100, 61, 49, 49, 54, 50, 51, 32, 97, 117, 105, 100, 61, 49, 48, 48, 48, 32, 117, 105, 100, 61, 49, 48, 48, 48, 32, 103, 105, 100, 61, 49, 48, 48, 48, 32, 101, 117, 105, 100, 61, 49, 48, 48, 48, 32, 115, 117, 105, 100, 61, 49, 48, 48, 48, 32, 102, 115, 117, 105, 100, 61, 49, 48, 48, 48, 32, 101, 103, 105, 100, 61, 49, 48, 48, 48, 32, 115, 103, 105, 100, 61, 49, 48, 48, 48, 32, 102, 115, 103, 105, 100, 61, 49, 48, 48, 48, 32, 116, 116, 121, 61, 112, 116, 115, 48, 32, 115, 101, 115, 61, 51, 53, 32, 99, 111, 109, 109, 61, 34, 108, 115, 34, 32, 101, 120, 101, 61, 34, 47, 98, 105, 110, 47, 108, 115, 34, 32, 107, 101, 121, 61, 40, 110, 117, 108, 108, 41}

	//&{1309,,argc=3,a0="ls",a1="--color=auto",a2="-alF",1222763,1459376866.885}
	data[1] = []byte{73, 0, 0, 0, 29, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 117, 100, 105, 116, 40, 49, 52, 53, 57, 51, 55, 54, 56, 54, 54, 46, 56, 56, 53, 58, 49, 50, 50, 50, 55, 54, 51, 41, 58, 32, 97, 114, 103, 99, 61, 51, 32, 97, 48, 61, 34, 108, 115, 34, 32, 97, 49, 61, 34, 45, 45, 99, 111, 108, 111, 114, 61, 97, 117, 116, 111, 34, 32, 97, 50, 61, 34, 45, 97, 108, 70, 34}

	//&{1307,,,cwd="/home/ubuntu/src/slack-github.com/rhuber/go-audit-new",1222763,1459376866.885}
	data[2] = []byte{91, 0, 0, 0, 27, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 117, 100, 105, 116, 40, 49, 52, 53, 57, 51, 55, 54, 56, 54, 54, 46, 56, 56, 53, 58, 49, 50, 50, 50, 55, 54, 51, 41, 58, 32, 32, 99, 119, 100, 61, 34, 47, 104, 111, 109, 101, 47, 117, 98, 117, 110, 116, 117, 47, 115, 114, 99, 47, 115, 108, 97, 99, 107, 45, 103, 105, 116, 104, 117, 98, 46, 99, 111, 109, 47, 114, 104, 117, 98, 101, 114, 47, 103, 111, 45, 97, 117, 100, 105, 116, 45, 110, 101, 119, 34}

	//&{1302,,item=0,name="/bin/ls",inode=262316,dev=ca:01,mode=0100755,ouid=0,ogid=0,rdev=00:00,nametype=NORMAL,1222763,1459376866.885}
	data[3] = []byte{129, 0, 0, 0, 22, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 117, 100, 105, 116, 40, 49, 52, 53, 57, 51, 55, 54, 56, 54, 54, 46, 56, 56, 53, 58, 49, 50, 50, 50, 55, 54, 51, 41, 58, 32, 105, 116, 101, 109, 61, 48, 32, 110, 97, 109, 101, 61, 34, 47, 98, 105, 110, 47, 108, 115, 34, 32, 105, 110, 111, 100, 101, 61, 50, 54, 50, 51, 49, 54, 32, 100, 101, 118, 61, 99, 97, 58, 48, 49, 32, 109, 111, 100, 101, 61, 48, 49, 48, 48, 55, 53, 53, 32, 111, 117, 105, 100, 61, 48, 32, 111, 103, 105, 100, 61, 48, 32, 114, 100, 101, 118, 61, 48, 48, 58, 48, 48, 32, 110, 97, 109, 101, 116, 121, 112, 101, 61, 78, 79, 82, 77, 65, 76}

	//&{1302,,item=1,name="/lib64/ld-linux-x86-64.so.2",inode=396037,dev=ca:01,mode=0100755,ouid=0,ogid=0,rdev=00:00,nametype=NORMAL,1222763,1459376866.885}
	data[4] = []byte{149, 0, 0, 0, 22, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 117, 100, 105, 116, 40, 49, 52, 53, 57, 51, 55, 54, 56, 54, 54, 46, 56, 56, 53, 58, 49, 50, 50, 50, 55, 54, 51, 41, 58, 32, 105, 116, 101, 109, 61, 49, 32, 110, 97, 109, 101, 61, 34, 47, 108, 105, 98, 54, 52, 47, 108, 100, 45, 108, 105, 110, 117, 120, 45, 120, 56, 54, 45, 54, 52, 46, 115, 111, 46, 50, 34, 32, 105, 110, 111, 100, 101, 61, 51, 57, 54, 48, 51, 55, 32, 100, 101, 118, 61, 99, 97, 58, 48, 49, 32, 109, 111, 100, 101, 61, 48, 49, 48, 48, 55, 53, 53, 32, 111, 117, 105, 100, 61, 48, 32, 111, 103, 105, 100, 61, 48, 32, 114, 100, 101, 118, 61, 48, 48, 58, 48, 48, 32, 110, 97, 109, 101, 116, 121, 112, 101, 61, 78, 79, 82, 77, 65, 76}

	//&{1320,,,1222763,1459376866.885}
	data[5] = []byte{31, 0, 0, 0, 40, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 117, 100, 105, 116, 40, 49, 52, 53, 57, 51, 55, 54, 56, 54, 54, 46, 56, 56, 53, 58, 49, 50, 50, 50, 55, 54, 51, 41, 58, 32}

	for i := 0; i < b.N; i++ {
		for n := 0; n < len(data); n++ {
			nlen := len(data[n])
			msg := &syscall.NetlinkMessage{
				Header: syscall.NlMsghdr{
					Len:   Endianness.Uint32(data[n][0:4]),
					Type:  Endianness.Uint16(data[n][4:6]),
					Flags: Endianness.Uint16(data[n][6:8]),
					Seq:   Endianness.Uint32(data[n][8:12]),
					Pid:   Endianness.Uint32(data[n][12:16]),
				},
				Data: data[n][syscall.SizeofNlMsghdr:nlen],
			}
			marshaller.Consume(msg)
		}
	}
}

type noopWriter struct{ t *testing.T }

func (t *noopWriter) Write(a []byte) (int, error) {
	return 0, nil
}

func createTempFile(t *testing.T, name string, contents string) string {
	file := os.TempDir() + string(os.PathSeparator) + "go-audit." + name
	if err := os.WriteFile(file, []byte(contents), os.FileMode(0644)); err != nil {
		t.Fatal("Failed to create temp file", err)
	}
	return file
}
