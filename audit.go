//There is one rule here. "thou shall not block"
//Slack Technologies, Inc 2015
//Ryan Huber
package main

import (
	"flag"
	"github.com/pkg/profile"
	"github.com/spf13/viper"
	"log"
	"log/syslog"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var l = log.New(os.Stdout, "", 0)
var el = log.New(os.Stderr, "", 0)

func loadConfig(config *viper.Viper) {
	config.SetDefault("canary", true)
	config.SetDefault("message_tracking.enabled", true)
	config.SetDefault("message_tracking.log_out_of_order", false)
	config.SetDefault("message_tracking.max_out_of_order", 500)
	config.SetDefault("output.syslog.enabled", false)
	config.SetDefault("output.syslog.priority", int(syslog.LOG_LOCAL0|syslog.LOG_WARNING))
	config.SetDefault("output.syslog.tag", "go-audit")
	config.SetDefault("output.syslog.attempts", "3")
	config.SetDefault("log.flags", 0)

	err := config.ReadInConfig() // Find and read the config file
	if err != nil {              // Handle errors reading the config file
		el.Printf("Config file has an error: %s\n", err)
		os.Exit(1)
	}
}

func setRules(config *viper.Viper) {
	// Clear existing rules
	err := exec.Command("auditctl", "-D").Run()
	if err != nil {
		el.Fatalf("Failed to flush existing audit rules. Error: %s\n", err)
	}

	l.Println("Flushed existing audit rules")

	// Add ours in
	if rules := config.GetStringSlice("rules"); len(rules) != 0 {
		for i, v := range rules {
			// Skip rules with no content
			if v == "" {
				continue
			}

			err := exec.Command("auditctl", strings.Fields(v)...).Run()
			if err != nil {
				el.Fatalf("Failed to add rule #%d. Error: %s \n", i+1, err)
			}

			l.Printf("Added audit rule #%d\n", i+1)
		}
	} else {
		el.Fatalln("No audit rules found. exiting")
	}
}

func createOutput(config *viper.Viper) *AuditWriter {
	if config.GetBool("output.syslog.enabled") == false {
		el.Fatalln("No outputs have been enabled")
	}

	attempts := config.GetInt("output.syslog.attempts")
	if attempts < 1 {
		el.Fatalln("output attempts for syslog must be at least 1", attempts, "provided")
	}

	syslogWriter, err := syslog.Dial(
		config.GetString("output.syslog.network"),
		config.GetString("output.syslog.address"),
		syslog.Priority(config.GetInt("output.syslog.priority")),
		config.GetString("output.syslog.tag"),
	)

	if err != nil {
		el.Fatalln("Failed to open syslog writer. Error:", err)
	}

	return NewAuditWriter(syslogWriter, attempts)
}

func createFilters(config *viper.Viper) []AuditFilter {
	var err error
	var ok bool

	fs := config.Get("filters")
	filters := []AuditFilter{}

	if fs == nil {
		return filters
	}

	ft, ok := fs.([]interface{})
	if !ok {
		return filters
	}

	for i, f := range ft {
		f2, ok := f.(map[interface{}]interface{})
		if !ok {
			el.Fatal("Could not parse filter ", i+1, f)
		}

		af := AuditFilter{}
		for k, v := range f2 {
			switch k {
			case "message_type":
				if ev, ok := v.(string); ok {
					fv, err := strconv.ParseUint(ev, 10, 64)
					if err != nil {
						el.Fatal("`message_type` in filter ", i+1, " could not be parsed ", v, " ", err)
					}
					af.messageType = uint16(fv)

				} else if ev, ok := v.(int); ok {
					if !ok {
						el.Fatal("`message_type` in filter ", i+1, " could not be parsed ", v)
					}
					af.messageType = uint16(ev)

				} else {
					el.Fatal("`message_type` in filter ", i+1, " could not be parsed ", v)
				}

			case "regex":
				re, ok := v.(string)
				if !ok {
					el.Fatal("`regex` in filter ", i+1, " could not be parsed ", v)
				}

				if af.regex, err = regexp.Compile(re); err != nil {
					el.Fatal("`regex` in filter ", i+1, " could not be parsed ", v, " ", err)
				}

			case "syscall":
				if af.syscall, ok = v.(string); ok {
					el.Fatal("`syscall` in filter ", i+1, " could not be parsed ", v)
				} else if ev, ok := v.(int); ok {
					af.syscall = strconv.Itoa(ev)
				} else {
					el.Fatal("`syscall` in filter ", i+1, " could not be parsed ", v)
				}
			}
		}

		filters = append(filters, af)
		l.Printf("Ignoring  syscall `%v` containing message type `%v` matching string `%s`\n", af.syscall, af.messageType, af.regex.String())
	}

	return filters
}

func main() {
	config := viper.New()
	configFile := flag.String("config", "", "Config file location")
	cpuProfile := flag.Bool("cpuprofile", false, "Enable cpu profiling")

	flag.Parse()

	if *configFile == "" {
		el.Println("A config file must be provided")
		flag.Usage()
		os.Exit(1)
	}

	config.SetConfigFile(*configFile)
	loadConfig(config)

	l.SetFlags(config.GetInt("log.flags"))
	el.SetFlags(config.GetInt("log.flags"))

	if config.GetBool("canary") {
		go canaryRead()
	}

	setRules(config)

	if *cpuProfile {
		l.Println("Enabling CPU profile ./cpu.pprof")
		defer profile.Start(profile.Quiet, profile.ProfilePath(".")).Stop()
	}

	writer := createOutput(config)
	nlClient := NewNetlinkClient(config.GetInt("socket_buffer.receive"))
	marshaller := NewAuditMarshaller(
		writer,
		config.GetBool("message_tracking.enabled"),
		config.GetBool("message_tracking.log_out_of_order"),
		config.GetInt("message_tracking.max_out_of_order"),
		createFilters(config),
	)

	l.Println("Started processing events")

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
