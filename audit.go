//There is one rule here. "thou shall not block"
//Slack Technologies, Inc 2015
//Ryan Huber
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime/pprof"
	"strings"

	"github.com/spf13/viper"
)

//Helper for profiling. Don't forget to "pprof.StopCPUProfile()" at some point or the file isn't written.
func profile() {
	f, err := os.Create("/tmp/profile")
	if err != nil {
		log.Fatal(err)
	}
	f2, err := os.Create("/tmp/profile2")
	if err != nil {
		log.Fatal(err)
	}
	pprof.StartCPUProfile(f)
	pprof.WriteHeapProfile(f2)
}

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
	auditLogger := log.New(os.Stdout, "", 0)
	nlClient := NewNetlinkClient()
	marshaller := NewAuditMarshaller(auditLogger)

	auditLogger.Print("Starting up")

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
