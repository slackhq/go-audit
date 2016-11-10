package main

import (
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"syscall"
	"testing"
)

func Test_loadConfig(t *testing.T) {
	config := viper.New()

	file := createTempFile(t, "defaultValues.test.yaml", "")
	defer os.Remove(file)

	config.SetConfigFile(file)
	loadConfig(config)
	assert.Equal(t, true, config.GetBool("message_tracking.enabled"), "message_tracking.enabled should default to true")
	assert.Equal(t, false, config.GetBool("message_tracking.log_out_of_order"), "message_tracking.log_out_of_order should default to false")
	assert.Equal(t, 500, config.GetInt("message_tracking.max_out_of_order"), "message_tracking.max_out_of_order should default to 500")
	assert.Equal(t, false, config.GetBool("output.syslog.enabled"), "output.syslog.enabled should default to false")
	assert.Equal(t, 132, config.GetInt("output.syslog.priority"), "output.syslog.priority should default to 132")
	assert.Equal(t, "go-audit", config.GetString("output.syslog.tag"), "output.syslog.tag should default to go-audit")
	assert.Equal(t, 3, config.GetInt("output.syslog.attempts"), "output.syslog.attempts should default to 3")
	assert.Equal(t, 0, config.GetInt("log.flags"), "log.flags should default to 0")

	//TODO: this doesn't work because loadConfig calls os.Exit
	//lb, elb := hookLogger()
	//defer resetLogger()
	//
	//file = createTempFile(t, "defaultValues.test.yaml", "this is bad")
	//loadConfig(config, file)
	//assert.Equal(t, "", lb.String(), "Got some log lines we did not expect")
	//assert.Equal(t, "Error occurred while trying to keep the connection: bad file descriptor\n", elb.String(), "Figured we would have an error")
}

func Test_loadConfig_fail(t *testing.T) {
	//TODO: test that we exit if the config file doesn't exist or is poorly formed
	t.Skip("Not implemented")
}

func Test_setRules(t *testing.T) {
	//TODO: Test rules are flushed first (success/fail)
	//TODO: Test rules are added (success/fail)
	//TODO: Test empty rule lines are skipped
	//TODO: Test fatal if no rules
	t.Skip("Not implemented")
}

func Test_createOutput(t *testing.T) {
	//TODO: Test all config settings are used
	//TODO: Test failure to connect to syslog
	//TODO: Test fatal if syslog is not enabled
	t.Skip("Not implemented")
}

func Test_main(t *testing.T) {
	//TODO: This one will be tricky in its current format
	t.Skip("Not implemented")
}

func Benchmark_MultiPacketMessage(b *testing.B) {
	marshaller := NewAuditMarshaller(NewAuditWriter(&noopWriter{}, 1), false, false, 1, []AuditFilter{})

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
	if err := ioutil.WriteFile(file, []byte(contents), os.FileMode(0644)); err != nil {
		t.Fatal("Failed to create temp file", err)
	}
	return file
}
