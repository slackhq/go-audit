//There is one rule here. "thou shall not block"
//Slack Technologies, Inc 2015
//Ryan Huber
package main

import (
	"os/exec"
	"strings"
	"github.com/pkg/profile"
	"github.com/spf13/viper"
	"log/syslog"
	"flag"
	"os"
	"io"
	"log"
)

var l, el *log.Logger

func loadConfig(config *viper.Viper, cFile string) {
	config.SetDefault("canary", true)
	config.SetDefault("message_tracking.enabled", true)
	config.SetDefault("message_tracking.log_out_of_order", false)
	config.SetDefault("message_tracking.max_out_of_order", 500)
	config.SetDefault("output.syslog.enabled", true)
	config.SetDefault("output.syslog.priority", int(syslog.LOG_LOCAL0 | syslog.LOG_WARNING))
	config.SetDefault("output.syslog.tag", "go-audit")
	config.SetDefault("log.flags", 0)

	config.SetConfigFile(cFile)

	err := config.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		el.Println("Config file %s has an error: %s\n", cFile, err)
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
				el.Fatalf("Failed to add rule #%d. Error: %s \n", i + 1, err)
			}

			l.Printf("Added audit rule #%d\n", i + 1)
		}
	} else {
		el.Fatalln("No audit rules found. exiting")
	}
}

func createOutput(config *viper.Viper) io.Writer {
	if config.GetBool("output.syslog.enabled") == false {
		el.Fatalln("No outputs have been enabled")
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

	return syslogWriter
}

func main() {
	l = log.New(os.Stdout, "", 0)
	el = log.New(os.Stderr, "", 0)

	config := viper.New()
	configFile := flag.String("config", "", "Config file location, default /etc/audit/go-audit.yaml")
	cpuProfile := flag.Bool("cpuprofile", false, "Enable cpu profiling")

	flag.Parse()

	if *configFile == "" {
		el.Println("A config file must be provided")
		flag.Usage()
		os.Exit(1)
	}

	loadConfig(config, *configFile)

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
