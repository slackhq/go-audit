package main

import (
	"errors"
	"flag"
	"fmt"
	"log/syslog"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/pantheon-systems/go-audit/pkg/output"
	"github.com/pantheon-systems/go-audit/pkg/slog"
	"github.com/spf13/viper"
)

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
	config.SetDefault("log.flags", 0)

	if err := config.ReadInConfig(); err != nil {
		return nil, err
	}

	slog.Configure(config.GetInt("log.flags"))

	return config, nil
}

func setRules(config *viper.Viper, e executor) error {
	// Clear existing rules
	if err := e("auditctl", "-D"); err != nil {
		return fmt.Errorf("Failed to flush existing audit rules. Error: %s", err)
	}

	slog.Info.Println("Flushed existing audit rules")

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

			slog.Info.Printf("Added audit rule #%d\n", i+1)
		}
	} else {
		return errors.New("No audit rules found")
	}

	return nil
}

func createOutput(config *viper.Viper) (*output.AuditWriter, error) {
	var writer *output.AuditWriter
	var err error
	enabledCount := 0

	for _, auditWriterName := range output.GetAvailableAuditWriters() {
		configName := "output." + auditWriterName + ".enabled"
		if config.GetBool(configName) == true {
			enabledCount++
			writer, err = output.CreateAuditWriter(auditWriterName, config)
			if err != nil {
				return nil, err
			}
		}
	}

	if enabledCount > 1 {
		return nil, errors.New("Only one output can be enabled at a time")
	}

	if writer == nil {
		return nil, errors.New("No outputs were configured")
	}

	return writer, nil
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

		if af.syscall == "" {
			return filters, fmt.Errorf("Filter %d is missing the `syscall` entry", i+1)
		}

		if af.messageType == 0 {
			return filters, fmt.Errorf("Filter %d is missing the `message_type` entry", i+1)
		}

		filters = append(filters, af)
		slog.Info.Printf("Ignoring syscall `%v` containing message type `%v` matching string `%s`\n", af.syscall, af.messageType, af.regex.String())
	}

	return filters, nil
}

func main() {
	configFile := flag.String("config", "", "Config file location")

	flag.Parse()

	if *configFile == "" {
		slog.Error.Println("A config file must be provided")
		flag.Usage()
		os.Exit(1)
	}

	config, err := loadConfig(*configFile)
	if err != nil {
		slog.Error.Fatal(err)
	}

	// output needs to be created before anything that write to stdout
	writer, err := createOutput(config)
	if err != nil {
		slog.Error.Fatal(err)
	}

	if err := setRules(config, lExec); err != nil {
		slog.Error.Fatal(err)
	}

	filters, err := createFilters(config)
	if err != nil {
		slog.Error.Fatal(err)
	}

	nlClient, err := NewNetlinkClient(config.GetInt("socket_buffer.receive"))
	if err != nil {
		slog.Error.Fatal(err)
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

	slog.Info.Printf("Started processing events in the range [%d, %d]\n", config.GetInt("events.min"), config.GetInt("events.max"))

	//Main loop. Get data from netlink and send it to the json lib for processing
	for {
		msg, err := nlClient.Receive()
		if err != nil {
			slog.Error.Printf("Error during message receive: %+v\n", err)
			continue
		}

		if msg == nil {
			continue
		}

		marshaller.Consume(msg)
	}
}
