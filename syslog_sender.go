package main

import (
	"log/syslog"
)

func logLine(data string) {
	my_log, _ := syslog.Dial("", "", syslog.LOG_INFO, "auditd")
	my_log.Write([]byte(data))
}
