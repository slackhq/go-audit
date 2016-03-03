package main

import (
	"fmt"
	"log/syslog"
)

var sysLog *syslog.Writer

func logLine(data string) {
	if sysLog == nil {
		sysLog, _ = syslog.Dial("", "", syslog.LOG_LOCAL0|syslog.LOG_WARNING, "auditd")
	}
	if data != "" {
		_, err := sysLog.Write([]byte(data))
		if err != nil {
			fmt.Printf("Failed to log item of length %d because of error %s\n", len(data), err)
		}
	}
}
