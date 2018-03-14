package output

import (
	"fmt"
	"log/syslog"
	"os"
	"os/signal"
	"syscall"

	"github.com/pantheon-systems/go-audit/pkg/slog"
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

	writer := NewAuditWriter(syslogWriter, attempts)
	go handleLogRotation(config, writer)
	return writer, nil
}

func handleLogRotation(config *viper.Viper, writer *AuditWriter) {
	// Re-open our log file. This is triggered by a USR1 signal and is meant to be used upon log rotation

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGUSR1)

	for range sigc {
		newWriter, err := newSyslogWriter(config)
		if err != nil {
			slog.Error.Fatalln("Error re-opening log file. Exiting.")
		}

		oldFile := writer.w.(*os.File)
		writer.w = newWriter.w
		writer.e = newWriter.e

		err = oldFile.Close()
		if err != nil {
			slog.Error.Printf("Error closing old log file: %+v\n", err)
		}
	}
}
