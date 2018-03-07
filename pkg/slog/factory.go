package slog

import (
	"log"
	"os"
)

var Info *log.Logger
var Error *log.Logger

func init() {
	Info = log.New(os.Stdout, "", 0)
	Error = log.New(os.Stderr, "", 0)
}

func Configure(flags int) {
	Info.SetFlags(flags)
	Error.SetFlags(flags)
}
