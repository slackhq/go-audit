package main

import (
	"log/syslog"
)

var my_log *syslog.Writer

func logLine(data string) {
	if my_log == nil {
		my_log, _ = syslog.Dial("", "", syslog.LOG_INFO, "auditd")
	}
	my_log.Write([]byte(data))
}
