package http_transformer

import (
	"encoding/json"
	"os"
	"regexp"
)

type NotificationServiceTransformer struct {
	hostname string
}

type notification struct {
	Topic      string            `json:"topic"`
	Attributes map[string]string `json:"attributes"`
	Data       string            `json:"data"`
	Version    string            `json:"version"`
}

var ruleKeyRegex = regexp.MustCompile(`"rule_key":"(.*)"`)

func init() {
	Register("notification-service", NotificationServiceTransformer{
		hostname: getHostname(),
	})
}

func (t NotificationServiceTransformer) Transform(body *[]byte) (*[]byte, error) {
	matches := ruleKeyRegex.FindStringSubmatch(string(*body))
	if len(matches) < 2 || matches[1] == "" {
		// not what we are looking for skip
		return nil, nil
	}

	notif := notification{
		Topic: matches[1],
		Data:  string(*body),
		Attributes: map[string]string{
			"hostname": t.hostname,
		},
		Version: "1.0.0",
	}

	transformedBody, err := json.Marshal(notif)
	if err != nil {
		return nil, err
	}

	return &transformedBody, nil
}

func getHostname() string {
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	return host
}
