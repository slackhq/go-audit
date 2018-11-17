package main

import (
	"compress/flate"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/viper"
	"gopkg.in/Graylog2/go-gelf.v2/gelf"
)

var l = log.New(os.Stdout, "", 0)
var el = log.New(os.Stderr, "", 0)

type executor func(string, ...string) error

func lExec(s string, a ...string) error {
	return exec.Command(s, a...).Run()
}

func loadConfig(configFile string) (*viper.Viper, error) {
	config := viper.New()
	config.SetConfigFile(configFile)

	config.SetDefault("events.min", 1300)
	config.SetDefault("events.max", 1399)
	config.SetDefault("message_tracking.enabled", true)
	config.SetDefault("message_tracking.log_out_of_order", false)
	config.SetDefault("message_tracking.max_out_of_order", 500)
	config.SetDefault("output.syslog.enabled", false)
	config.SetDefault("output.syslog.priority", int(syslog.LOG_LOCAL0|syslog.LOG_WARNING))
	config.SetDefault("output.syslog.tag", "go-audit")
	config.SetDefault("output.syslog.attempts", "3")
	config.SetDefault("output.gelf.attempts", 3)
	config.SetDefault("output.gelf.network", "udp")
	config.SetDefault("output.gelf.compression.level", int(flate.BestSpeed))
	config.SetDefault("output.gelf.compression.type", int(gelf.CompressGzip))
	config.SetDefault("log.flags", 0)

	if err := config.ReadInConfig(); err != nil {
		return nil, err
	}

	l.SetFlags(config.GetInt("log.flags"))
	el.SetFlags(config.GetInt("log.flags"))

	return config, nil
}

func setRules(config *viper.Viper, e executor) error {
	// Clear existing rules
	if err := e("auditctl", "-D"); err != nil {
		return fmt.Errorf("Failed to flush existing audit rules. Error: %s", err)
	}

	l.Println("Flushed existing audit rules")

	// Add ours in
	if rules := config.GetStringSlice("rules"); len(rules) != 0 {
		for i, v := range rules {
			// Skip rules with no content
			if v == "" {
				continue
			}

			if err := e("auditctl", strings.Fields(v)...); err != nil {
				return fmt.Errorf("Failed to add rule #%d. Error: %s", i+1, err)
			}

			l.Printf("Added audit rule #%d\n", i+1)
		}
	} else {
		return errors.New("No audit rules found")
	}

	return nil
}

func createOutput(config *viper.Viper) (*AuditWriter, error) {
	var writer *AuditWriter
	var err error
	i := 0

	if config.GetBool("output.syslog.enabled") == true {
		i++
		writer, err = createSyslogOutput(config)
		if err != nil {
			return nil, err
		}
	}

	if config.GetBool("output.file.enabled") == true {
		i++
		writer, err = createFileOutput(config)
		if err != nil {
			return nil, err
		}

		go handleLogRotation(config, writer)
	}

	if config.GetBool("output.stdout.enabled") == true {
		i++
		writer, err = createStdOutOutput(config)
		if err != nil {
			return nil, err
		}
	}

	if config.GetBool("output.gelf.enabled") == true {
		i++
		writer, err = createGELFOutput(config)
		if err != nil {
			return nil, err
		}
	}

	if i > 1 {
		return nil, errors.New("Only one output can be enabled at a time")
	}

	if writer == nil {
		return nil, errors.New("No outputs were configured")
	}

	return writer, nil
}

func createGELFOutput(config *viper.Viper) (*AuditWriter, error) {
	attempts := config.GetInt("output.gelf.attempts")
	if attempts < 1 {
		return nil, fmt.Errorf("Output attempts for GELF must be at least 1, %v provided", attempts)
	}

	address := config.GetString("output.gelf.address")
	if address == "" {
		return nil, fmt.Errorf("Output address for GELF must be set")
	}

	switch config.GetString("output.gelf.network") {
	case "udp":
		writer, err := gelf.NewUDPWriter(address)
		if err != nil {
			return nil, err
		}

		writer.CompressionType = gelf.CompressType(config.GetInt("output.gelf.compression.type"))
		writer.CompressionLevel = config.GetInt("output.gelf.compression.level")

		return NewAuditWriter(writer, attempts), nil
	case "tcp":
		writer, err := gelf.NewTCPWriter(address)
		if err != nil {
			return nil, err
		}

		return NewAuditWriter(writer, attempts), nil
	default:
		return nil, fmt.Errorf("unsupported network by GELF library")
	}

}

func createSyslogOutput(config *viper.Viper) (*AuditWriter, error) {
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

func createFileOutput(config *viper.Viper) (*AuditWriter, error) {
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

func handleLogRotation(config *viper.Viper, writer *AuditWriter) {
	// Re-open our log file. This is triggered by a USR1 signal and is meant to be used upon log rotation

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGUSR1)

	for range sigc {
		newWriter, err := createFileOutput(config)
		if err != nil {
			el.Fatalln("Error re-opening log file. Exiting.")
		}

		oldFile := writer.w.(*os.File)
		writer.w = newWriter.w
		writer.e = newWriter.e

		err = oldFile.Close()
		if err != nil {
			el.Printf("Error closing old log file: %+v\n", err)
		}
	}
}

func createStdOutOutput(config *viper.Viper) (*AuditWriter, error) {
	attempts := config.GetInt("output.stdout.attempts")
	if attempts < 1 {
		return nil, fmt.Errorf("Output attempts for stdout must be at least 1, %v provided", attempts)
	}

	// l logger is no longer stdout
	l.SetOutput(os.Stderr)

	return NewAuditWriter(os.Stdout, attempts), nil
}

func createFilters(config *viper.Viper) ([]AuditFilter, error) {
	var err error
	var ok bool

	fs := config.Get("filters")
	filters := []AuditFilter{}

	if fs == nil {
		return filters, nil
	}

	ft, ok := fs.([]interface{})
	if !ok {
		return filters, fmt.Errorf("Could not parse filters object")
	}

	for i, f := range ft {
		f2, ok := f.(map[interface{}]interface{})
		if !ok {
			return filters, fmt.Errorf("Could not parse filter %d; '%+v'", i+1, f)
		}

		af := AuditFilter{}
		for k, v := range f2 {
			switch k {
			case "message_type":
				if ev, ok := v.(string); ok {
					fv, err := strconv.ParseUint(ev, 10, 64)
					if err != nil {
						return filters, fmt.Errorf("`message_type` in filter %d could not be parsed; Value: `%+v`; Error: %s", i+1, v, err)
					}
					af.messageType = uint16(fv)

				} else if ev, ok := v.(int); ok {
					af.messageType = uint16(ev)

				} else {
					return filters, fmt.Errorf("`message_type` in filter %d could not be parsed; Value: `%+v`", i+1, v)
				}

			case "regex":
				re, ok := v.(string)
				if !ok {
					return filters, fmt.Errorf("`regex` in filter %d could not be parsed; Value: `%+v`", i+1, v)
				}

				if af.regex, err = regexp.Compile(re); err != nil {
					return filters, fmt.Errorf("`regex` in filter %d could not be parsed; Value: `%+v`; Error: %s", i+1, v, err)
				}

			case "syscall":
				if af.syscall, ok = v.(string); ok {
					// All is good
				} else if ev, ok := v.(int); ok {
					af.syscall = strconv.Itoa(ev)
				} else {
					return filters, fmt.Errorf("`syscall` in filter %d could not be parsed; Value: `%+v`", i+1, v)
				}
			}
		}

		if af.regex == nil {
			return filters, fmt.Errorf("Filter %d is missing the `regex` entry", i+1)
		}

		if af.messageType == 0 {
			return filters, fmt.Errorf("Filter %d is missing the `message_type` entry", i+1)
		}

		filters = append(filters, af)
		l.Printf("Ignoring syscall `%v` containing message type `%v` matching string `%s`\n", af.syscall, af.messageType, af.regex.String())
	}

	return filters, nil
}

func main() {
	configFile := flag.String("config", "", "Config file location")

	flag.Parse()

	if *configFile == "" {
		el.Println("A config file must be provided")
		flag.Usage()
		os.Exit(1)
	}

	config, err := loadConfig(*configFile)
	if err != nil {
		el.Fatal(err)
	}

	// output needs to be created before anything that write to stdout
	writer, err := createOutput(config)
	if err != nil {
		el.Fatal(err)
	}

	if err := setRules(config, lExec); err != nil {
		el.Fatal(err)
	}

	filters, err := createFilters(config)
	if err != nil {
		el.Fatal(err)
	}

	nlClient, err := NewNetlinkClient(config.GetInt("socket_buffer.receive"))
	if err != nil {
		el.Fatal(err)
	}

	marshaller := NewAuditMarshaller(
		writer,
		uint16(config.GetInt("events.min")),
		uint16(config.GetInt("events.max")),
		config.GetBool("message_tracking.enabled"),
		config.GetBool("message_tracking.log_out_of_order"),
		config.GetInt("message_tracking.max_out_of_order"),
		filters,
	)

	l.Printf("Started processing events in the range [%d, %d]\n", config.GetInt("events.min"), config.GetInt("events.max"))

	//Main loop. Get data from netlink and send it to the json lib for processing
	for {
		msg, err := nlClient.Receive()
		if err != nil {
			el.Printf("Error during message receive: %+v\n", err)
			continue
		}

		if msg == nil {
			continue
		}

		marshaller.Consume(msg)
	}
}
