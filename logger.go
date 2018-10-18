package audit

import (
	"log"
	"os"
)

var Std = log.New(os.Stdout, "", 0)
var Stderr = log.New(os.Stderr, "", 0)
