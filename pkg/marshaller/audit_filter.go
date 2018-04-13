package marshaller

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/pantheon-systems/go-audit/pkg/slog"
)

type AuditFilter struct {
	MessageType uint16
	Regex       *regexp.Regexp
	Syscall     string
	Key         string
}

func NewAuditFilter(ruleNumber int, obj map[interface{}]interface{}) (*AuditFilter, error) {
	var err error
	var ok bool
	af := &AuditFilter{}
	for k, v := range obj {
		switch k {
		case "message_type":
			if ev, ok := v.(string); ok {
				fv, err := strconv.ParseUint(ev, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("`message_type` in filter %d could not be parsed; Value: `%+v`; Error: %s", ruleNumber, v, err)
				}
				af.MessageType = uint16(fv)

			} else if ev, ok := v.(int); ok {
				af.MessageType = uint16(ev)

			} else {
				return nil, fmt.Errorf("`message_type` in filter %d could not be parsed; Value: `%+v`", ruleNumber, v)
			}

		case "regex":
			re, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("`regex` in filter %d could not be parsed; Value: `%+v`", ruleNumber, v)
			}

			if af.Regex, err = regexp.Compile(re); err != nil {
				return nil, fmt.Errorf("`regex` in filter %d could not be parsed; Value: `%+v`; Error: %s", ruleNumber, v, err)
			}

		case "syscall":
			if af.Syscall, ok = v.(string); ok {
				// All is good
			} else if ev, ok := v.(int); ok {
				af.Syscall = strconv.Itoa(ev)
			} else {
				return nil, fmt.Errorf("`syscall` in filter %d could not be parsed; Value: `%+v`", ruleNumber, v)
			}
		case "key":
			if af.Key, ok = v.(string); !ok {
				return nil, fmt.Errorf("`key` in filter %d could not be parsed; Value: `%+v`", ruleNumber, v)
			}
		}
	}

	if af.Regex == nil {
		return nil, fmt.Errorf("Filter %d is missing the `regex` entry", ruleNumber)
	}

	logMsg := fmt.Sprintf("Ignoring messages with key `%s` matching string `%s`\n", af.Key, af.Regex.String())
	if af.Key == "" {
		if af.Syscall == "" && af.MessageType == 0 {
			return nil, fmt.Errorf("Filter %d is missing either the `key` entry or `syscall` and `message_type` entry", ruleNumber)
		}

		if af.Syscall == "" {
			return nil, fmt.Errorf("Filter %d is missing the `syscall` entry", ruleNumber)
		}

		if af.MessageType == 0 {
			return nil, fmt.Errorf("Filter %d is missing the `message_type` entry", ruleNumber)
		}

		logMsg = fmt.Sprintf("Ignoring syscall `%v` containing message type `%v` matching string `%s`\n", af.Syscall, af.MessageType, af.Regex.String())
	}
	slog.Info.Print(logMsg)
	return af, nil
}
