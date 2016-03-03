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
func makeJsonString(evBuf map[int]map[string]string, dtype uint16, dstring string) string {
	data := strings.Fields(dstring)
	_, seq := parseAuditHeader(data[0])
	//this shortcuts sending events that don't have an id.
	//since we recapture the socket every 5s, this eliminates a lot of useless info
	if seq == 0 {
		delete(evBuf, seq)
		return ""
	}
	if _, ok := evBuf[seq]; ok == false {
		evBuf[seq] = make(map[string]string)
	}
	splitz := []string{}

	//Add in some additional data
	evBuf[seq]["netlink_type"] = fmt.Sprintf("%d", dtype)
	evBuf[seq]["auditd_seq"] = fmt.Sprintf("%d", seq)

	//Divide into key value pairs for conversion to json
	for i := 0; i < len(data); i++ {
		a := data
		splitz = strings.SplitN(a[i], "=", 2)
		switch len(splitz) {
		//This means we found a key/value pair
		case 2:
			//leaving this here to test overwritten values
			//if evBuf[seq][splitz[0]] != "" {
			//	fmt.Println("overwrite! ", splitz[0])
			//}
			evBuf[seq][splitz[0]] = splitz[1]
			switch splitz[0] {
			//Get arg count and generate complete "command" element.

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
	switch {
	//If the message is anything from 13xx(audit) but not 1320, lets combine them so don't output yet
	//Also ignore 1305 because it is just a config change and has no end
	case ((dtype >= 1300 && dtype <= 1319) || (dtype >= 1300 && dtype <= 1319)) && (dtype != 1305):
		//fmt.Println(evBuf[seq])
	default:
		parseArgs(evBuf[seq])
		jstring := mapToJsonString(evBuf[seq])
		delete(evBuf, seq)
		return jstring
		//End of the event - send to channel to process
		//This is a brutal hack and we need to detect the EOE properly
	}
	return ""

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
			if len(m[element]) > 0 {
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
			} else {
				log.Printf("Failed to parse args in " + fmt.Sprintf("%s", m))
			}

		}
		//Store assembled command text into "command" key in passed map
		//Drop the first character, which is always a space
		m["command"] = string(command)[1:]
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
