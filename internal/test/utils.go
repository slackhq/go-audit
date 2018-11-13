package test

import (
	"bytes"
	"log"
	"os"
)

// Resets global loggers
func ResetLogger(std, stderr *log.Logger) {
	std.SetOutput(os.Stdout)
	stderr.SetOutput(os.Stderr)
}

// Hooks the global loggers writers so you can assert their contents
func HookLogger(std, stderr *log.Logger) (lb *bytes.Buffer, elb *bytes.Buffer) {
	lb = &bytes.Buffer{}
	std.SetOutput(lb)

	elb = &bytes.Buffer{}
	stderr.SetOutput(elb)
	return
}
