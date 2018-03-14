package output

import (
	"fmt"
	"os"

	"github.com/pantheon-systems/go-audit/pkg/slog"
	"github.com/spf13/viper"
)

func init() {
	register("stdout", newStdOutWriter)
}

func newStdOutWriter(config *viper.Viper) (*AuditWriter, error) {
	attempts := config.GetInt("output.stdout.attempts")
	if attempts < 1 {
		return nil, fmt.Errorf("Output attempts for stdout must be at least 1, %v provided", attempts)
	}

	// info logger is no longer stdout
	slog.Info.SetOutput(os.Stderr)

	return NewAuditWriter(os.Stdout, attempts), nil
}
