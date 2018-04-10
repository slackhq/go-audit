package output

import (
	"encoding/json"
	"fmt"
	"github.com/spf13/viper"
	"net/http"
)

// NotificationServiceWriter is a writer built on the HTTPWriter that specifically writes to the
// pantheon notification service
type NotificationServiceWriter struct {
	HTTPWriter
}

func init() {
	register("notification-service-writer", newNotificationServiceWriter)
}

func newNotificationServiceWriter(config *viper.Viper) (*AuditWriter, error) {
	var err error

	attempts := config.GetInt("output.notification-service.attempts")
	if attempts < 1 {
		return nil, fmt.Errorf("Output attempts for http must be at least 1, %v provided", attempts)
	}

	serviceURL := config.GetString("output.notification-service.url")
	workerCount := config.GetInt("output.notification-service.worker_count")
	bufferSize := config.GetInt("output.notification-service.buffer_size")

	var httpClient = &http.Client{}
	if config.IsSet("output.notification-service.ssl") && config.GetBool("output.notification-service.ssl") {
		clientCertPath := config.GetString("output.notification-service.client_cert")
		clientKeyPath := config.GetString("output.notification-service.client_key")
		caCertPath := config.GetString("output.notification-service.ca_cert")
		httpClient, err = createSSLClient(clientCertPath, clientKeyPath, caCertPath)
		if err != nil {
			return nil, err
		}
	}

	writer, err := createHTTPWriter(httpClient, bufferSize, workerCount, serviceURL)
	if err != nil {
		return nil, err
	}

	notifServWriter := &NotificationServiceWriter{
		HTTPWriter: *writer,
	}
	notifServWriter.responseBodyTranformer = notifServWriter.bodyTranformer
	return NewAuditWriter(notifServWriter, attempts), nil
}

func (w *NotificationServiceWriter) bodyTranformer(auditMessage *[]byte) *[]byte {
	matches := ruleKeyRegex.FindStringSubmatch(string(*auditMessage))
	if len(matches) < 2 || matches[1] == "" {
		return nil
	}

	notif := notification{
		Topic: matches[1],
		Data:  string(*auditMessage),
		Attributes: map[string]string{
			"hostname": w.hostname,
		},
		Version: "1.0.0",
	}

	body, err := json.Marshal(notif)
	if err != nil {
		return nil
	}

	return &body
}
