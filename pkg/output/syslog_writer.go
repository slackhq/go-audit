package output

import (
	"fmt"
	"log/syslog"

	"github.com/spf13/viper"
)

func init() {
	register("syslog", newSyslogWriter)
}

func newSyslogWriter(config *viper.Viper) (*AuditWriter, error) {
	attempts := config.GetInt("output.syslog.attempts")
	if attempts < 1 {
		return nil, fmt.Errorf("Output attempts for syslog must be at least 1, %v provided", attempts)
	}

	syslogWriter, err := syslog.Dial(
		config.GetString("output.syslog.network"),
		config.GetString("output.syslog.address"),
		syslog.Priority(config.GetInt("output.syslog.priority")),
		config.GetString("output.syslog.tag"),
	)

	if err != nil {
		return nil, fmt.Errorf("Failed to open syslog writer. Error: %v", err)
	}

	return NewAuditWriter(syslogWriter, attempts), nil
}
