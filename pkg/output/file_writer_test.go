package output

import (
	"os"
	"os/user"
	"path"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func Test_newFileWriter(t *testing.T) {
	// attempts error
	c := viper.New()
	c.Set("output.file.attempts", 0)
	w, err := newFileWriter(c)
	assert.EqualError(t, err, "Output attempts for file must be at least 1, 0 provided")
	assert.Nil(t, w)

	// failure to create/open file
	c = viper.New()
	c.Set("output.file.attempts", 1)
	c.Set("output.file.path", "/do/not/exist/please")
	c.Set("output.file.mode", 0644)
	w, err = newFileWriter(c)
	assert.EqualError(t, err, "Failed to open output file. Error: open /do/not/exist/please: no such file or directory")
	assert.Nil(t, w)

	// chmod error
	c = viper.New()
	c.Set("output.file.attempts", 1)
	c.Set("output.file.path", path.Join(os.TempDir(), "go-audit.test.log"))
	w, err = newFileWriter(c)
	assert.EqualError(t, err, "Output file mode should be greater than 0000")
	assert.Nil(t, w)

	// uid error
	c = viper.New()
	c.Set("output.file.attempts", 1)
	c.Set("output.file.path", path.Join(os.TempDir(), "go-audit.test.log"))
	c.Set("output.file.mode", 0644)
	w, err = newFileWriter(c)
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
	w, err = newFileWriter(c)
	assert.EqualError(t, err, "Could not find gid for group . Error: group: unknown group ")
	assert.Nil(t, w)

	// chown error
	c = viper.New()
	c.Set("output.file.attempts", 1)
	c.Set("output.file.path", path.Join(os.TempDir(), "go-audit.test.log"))
	c.Set("output.file.mode", 0644)
	c.Set("output.file.user", "root")
	c.Set("output.file.group", "root")
	w, err = newFileWriter(c)
	assert.EqualError(t, err, "Could not chown output file. Error: chown /tmp/go-audit.test.log: operation not permitted")
	assert.Nil(t, w)

	// All good
	c = viper.New()
	c.Set("output.file.attempts", 1)
	c.Set("output.file.path", path.Join(os.TempDir(), "go-audit.test.log"))
	c.Set("output.file.mode", 0644)
	c.Set("output.file.user", u.Username)
	c.Set("output.file.group", g.Name)
	w, err = newFileWriter(c)
	assert.Nil(t, err)
	assert.NotNil(t, w)
	assert.IsType(t, &os.File{}, w.w)
}

func Test_fileRotation(t *testing.T) {
	uid = os.Getuid()
	gid = os.Getgid()
	u, _ = user.LookupId(strconv.Itoa(uid))
	g, _ = user.LookupGroupId(strconv.Itoa(gid))

	// travis-ci is silly
	if u.Username == "" {
		u.Username = g.Name
	}

	// File rotation
	os.Rename(path.Join(os.TempDir(), "go-audit.test.log"), path.Join(os.TempDir(), "go-audit.test.log.rotated"))
	_, err = os.Stat(path.Join(os.TempDir(), "go-audit.test.log"))
	assert.True(t, os.IsNotExist(err))
	syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)
	time.Sleep(100 * time.Millisecond)
	_, err = os.Stat(path.Join(os.TempDir(), "go-audit.test.log"))
	assert.Nil(t, err)
}
