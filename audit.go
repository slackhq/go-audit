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
	"syscall"

	"github.com/spf13/viper"
)

var count int

func ping(count *int, interval int) bool {
	*count++
	return (*count % interval) == 0
}

func connect() (conn *NetlinkConnection) {
	conn, err := newNetlinkConnection()
	if err != nil {
		log.Fatal(err)
	}
	return

}

func startFlow(conn *NetlinkConnection) {
	//this mask starts the flow
	var ret []byte
	a, err := newAuditStatusPayload()
	a.Mask = 4
	a.Enabled = 1
	a.Pid = uint32(syscall.Getpid())

	n := newNetlinkPacket(1001)

	ret, _ = AuditRequestSerialize(n, a)
	//PrettyPacketSplit(ret, []int{32, 48, 64, 96, 128, 160, 192, 224, 256, 288})

	err = conn.Send(&ret)
	if err != nil {
		fmt.Println("something broke")
	}
}

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

	//This buffer holds partial events because they come as associated but separate lines from the kernel
	eventBuffer := make(map[int]map[string]string)

	conn := connect()
	startFlow(conn)

	//Main loop. Get data from netlink and send it to the json lib for processing
	for {
		data, _ := conn.Receive()
		header := readNetlinkPacketHeader(data[:16])
		dstring := fmt.Sprintf("%s", data[16:])
		jstring := makeJsonString(eventBuffer, header.Type, dstring)
		if jstring != "" {
			logLine(jstring)
		}
	}
}
