package output

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"

	"github.com/spf13/viper"
)

func init() {
	register("file", newFileWriter)
}

func newFileWriter(config *viper.Viper) (*AuditWriter, error) {
	attempts := config.GetInt("output.file.attempts")
	if attempts < 1 {
		return nil, fmt.Errorf("Output attempts for file must be at least 1, %v provided", attempts)
	}

	mode := os.FileMode(config.GetInt("output.file.mode"))
	if mode < 1 {
		return nil, errors.New("Output file mode should be greater than 0000")
	}

	f, err := os.OpenFile(
		config.GetString("output.file.path"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, mode,
	)

	if err != nil {
		return nil, fmt.Errorf("Failed to open output file. Error: %s", err)
	}

	if err := f.Chmod(mode); err != nil {
		return nil, fmt.Errorf("Failed to set file permissions. Error: %s", err)
	}

	uname := config.GetString("output.file.user")
	u, err := user.Lookup(uname)
	if err != nil {
		return nil, fmt.Errorf("Could not find uid for user %s. Error: %s", uname, err)
	}

	gname := config.GetString("output.file.group")
	g, err := user.LookupGroup(gname)
	if err != nil {
		return nil, fmt.Errorf("Could not find gid for group %s. Error: %s", gname, err)
	}

	uid, err := strconv.ParseInt(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("Found uid could not be parsed. Error: %s", err)
	}

	gid, err := strconv.ParseInt(g.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("Found gid could not be parsed. Error: %s", err)
	}

	if err = f.Chown(int(uid), int(gid)); err != nil {
		return nil, fmt.Errorf("Could not chown output file. Error: %s", err)
	}

	return NewAuditWriter(f, attempts), nil
}
