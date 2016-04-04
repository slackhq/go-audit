//There is one rule here. "thou shall not block"
//Slack Technologies, Inc 2015
//Ryan Huber
package main

import (
	"fmt"
	"os/exec"
	"strings"
	"github.com/pkg/profile"
	"github.com/spf13/viper"
	"log/syslog"
	"flag"
)

func loadConfig(configLocation string) {
	if configLocation == "" {
		viper.SetConfigName("go-audit")
		viper.AddConfigPath("/etc/audit")
		viper.AddConfigPath(".")
	} else {
		viper.SetConfigFile(configLocation)
	}

	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		fmt.Println("Config not found. Running in default mode. (forwarding all events to syslog)")
		return
	}

	fmt.Println("Using config from", viper.ConfigFileUsed())
}

func main() {
	configFile := flag.String("config", "", "Config file location, default /etc/audit/go-audit.yaml")
	cpuProfile := flag.Bool("cpuprofile", false, "Enable cpu profiling")

	flag.Parse()

	loadConfig(*configFile)

	if viper.GetBool("canary") {
		go canaryRead()
	}

	if rules := viper.GetStringSlice("rules"); len(rules) != 0 {
		for _, v := range rules {
			err := exec.Command("auditctl", strings.Fields(v)...).Run()
			if err != nil {
				//TODO: this should probably be a fatal
				fmt.Println("auditctl exit info: ", err)
			}
		}
	} else {
		fmt.Println("No rules found. Running with existing ruleset (may be empty!)")
	}

	if *cpuProfile {
		fmt.Println("Enabling CPU profile ./cpu.pprof")
		defer profile.Start(profile.Quiet, profile.ProfilePath(".")).Stop()
	}

	//TODO: syslogWriter should be configurable
	syslogWriter, _ := syslog.Dial("", "", syslog.LOG_LOCAL0 | syslog.LOG_WARNING, "go-audit")
	nlClient := NewNetlinkClient()
	marshaller := NewAuditMarshaller(syslogWriter)

	//Main loop. Get data from netlink and send it to the json lib for processing
	for {
		msg, err := nlClient.Receive()
		if err != nil {
			fmt.Println("Error during message receive:", err)
			continue
		}

		marshaller.Consume(msg)
	}
}
