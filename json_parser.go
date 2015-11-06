package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os/user"
	"strconv"
	"strings"
)

var uidMap = map[string]user.User{}

//This does the heavy lifting of making auditd messages into json.
//It is NOT thread (goroutine) safe, as it uses two shared global maps
//It can be made threadsafe by locking these if performance becomes an issue.
func makeJsonString(evBuf map[int]map[string]string, dstring string, c chan<- string) {
	data := strings.Fields(dstring)
	_, seq := parseAuditHeader(data[0])
	if _, ok := evBuf[seq]; ok == false {
		evBuf[seq] = make(map[string]string)
	}
	//End of the event - send to channel to process
	//This is a brutal hack and we need to detect the EOE properly
	if len(data) == 1 {
		c <- mapToJsonString(evBuf[seq])
		delete(evBuf, seq)
	}
	splitz := []string{}

	//Divide into key value pairs for conversion to json
	for i := 0; i < len(data); i++ {
		a := data
		splitz = strings.SplitN(a[i], "=", 2)
		switch len(splitz) {
		//This means we found a key/value pair
		case 2:
			evBuf[seq][splitz[0]] = splitz[1]
			switch splitz[0] {
			//Get arg count and generate complete "command" element.
			case "argc":
				defer parseArgs(evBuf[seq])
			//Add contextual info per host if we can look up the uid
			case "uid":
				parseUid(evBuf[seq], "uid")
			case "auid":
				parseUid(evBuf[seq], "auid")
			}
		//Empty case here because this is what the header looks like and we don't want to error
		case 1:
		//This shouldn't happen
		default:
			log.Fatal("unexpected split: ", splitz)
		}
	}

}

//Parses the auditd headers. Example: 'audit(1446832550.594:2767175):'
//Where the first number in parens is the timestamp
//and the second is the sequence number of the event
func parseAuditHeader(data string) (time string, seq int) {
	if len(data) > 6 && data[:6] == "audit(" {
		timeAndSeq := strings.Split(strings.Trim(data, "audit():"), ":")
		seq, _ := strconv.Atoi(timeAndSeq[1])
		return timeAndSeq[0], seq
	} else {
		return
	}
}

//Iterates over argc(int) and combines individual a[num] into a single "command" key
func parseArgs(m map[string]string) {
	argc, _ := strconv.Atoi(m["argc"])
	if _, ok := m["argc"]; ok {
		command := []byte{}
		for i := 0; i < argc; i++ {
			element := fmt.Sprintf("a%d", i)
			//If surrounded by quotes, it is a literal. Just remove the double quotes.
			//If not surrounded by quotes, it is hex encoded. Decode the text.
			if m[element][0] == '"' {
				m[element] = strings.Trim(m[element], "\"")
				command = append(command, ' ')
				command = append(command, m[element]...)

			} else {
				n, _ := hex.DecodeString(m[element])
				command = append(command, ' ')
				command = append(command, n...)
				m[element] = string(n)
			}
		}
		//Store assembled command text into "command" key in passed map
		m["command"] = string(command)
	}
}

//Simple wrapper to make the map into json
func mapToJsonString(m map[string]string) string {
	s, err := json.Marshal(m)
	if err != nil {
		log.Fatal(err)
	}
	out := fmt.Sprintf("%s", s)
	return out
}

//This takes the map to modify and a key name and adds the username to a new key with "_username"
func parseUid(m map[string]string, uidKey string) {
	//Make sure we have a uid element to work with.
	if uid, ok := m[uidKey]; ok {
		//Give a default value in case we don't find something.
		m[uidKey+"_username"] = "UNKNOWN_USER"
		if luser, ok := uidMap[uid]; ok {
			m[uidKey+"_username"] = luser.Username
		} else {
			luser, err := user.LookupId(uid)
			if err == nil {
				m[uidKey+"_username"] = luser.Username
				uidMap[uid] = *luser
				//Probably redundant. FIX
			} else {
				uidMap[uid] = user.User{Username: "UNKNOWN_USER"}
			}
		}
	}
}
