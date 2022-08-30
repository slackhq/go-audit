package main

import (
	"strconv"
	"strings"
)

func getPid(data string) (pid, ppid int) {
	start := 0
	end := 0
	var err error

	for {
		if start = strings.Index(data, "pid="); start < 0 {
			return
		}

		// Progress the start point beyon the = sign
		start += 4
		if end = strings.IndexByte(data[start:], spaceChar); end < 0 {
			// There was no ending space, maybe the pid is at the end of the line
			end = len(data) - start

			// If the end of the line is greater than 7 characters away (overflows 22 bit uint) then it can't be a pid
			// > On 64-bit systems, pid_max can be set to any value up to 2^22 (PID_MAX_LIMIT, approximately 4 million).
			if end > 7 {
				return
			}
		}

		id := data[start : start+end]
		if start > 4 && data[start-5] == 'p' {
			ppid, err = strconv.Atoi(id)
		} else {
			pid, err = strconv.Atoi(id)
		}
		if err != nil {
			el.Printf("Failed to parse pid: %s: %v\n", id, err)
		}
		if pid != 0 && ppid != 0 {
			return
		}

		data = data[start+end:]
	}
}
