package main

import (
	"log/syslog"
)

var sysLog *syslog.Writer

func logLine(data string) {
	if sysLog == nil {
		sysLog, _ = syslog.Dial("", "", syslog.LOG_LOCAL0|syslog.LOG_WARNING, "auditd")
	}
	if data != "" {
		sysLog.Write([]byte(data))
	}
}
