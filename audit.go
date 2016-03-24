//There is one rule here. "thou shall not block"
//Slack Technologies, Inc 2015
//Ryan Huber
package main

import (
	"fmt"
	"os/exec"
	"strings"
	//"github.com/pkg/profile"
	"github.com/spf13/viper"
	"log/syslog"
)

func loadConfig() {
	go canaryRead()
	viper.SetConfigName("go-audit")
	viper.AddConfigPath("/etc/audit")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		fmt.Println("Config not found. Running in default mode. (forwarding all events to syslog)")
		return
	}
	if viper.GetBool("canary") {
		go canaryGo(viper.GetString("canary_host"), viper.GetString("canary_port"))
	}
	if rules := viper.GetStringSlice("rules"); len(rules) != 0 {
		for _, v := range rules {
			var _ = v
			v := strings.Fields(v)
			err := exec.Command("auditctl", v...).Run()
			if err != nil {
				fmt.Println("auditctl exit info: ", err)
			}
		}
	} else {
		fmt.Println("No rules found. Running with existing ruleset (may be empty!)")
	}
}

func main() {
	loadConfig()

	//TODO: auditLogger should be configurable
	syslogWriter, _ := syslog.Dial("", "", syslog.LOG_LOCAL0|syslog.LOG_WARNING, "auditd")
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
