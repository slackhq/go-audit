package output

import (
	"fmt"

	"github.com/spf13/viper"
)

type PubSubWriter struct {
}

func init() {
	register("pubsub", newPubSubWriter)
}

func (w *PubSubWriter) Write(p []byte) (n int, err error) {
	return 0, nil
}

func newPubSubWriter(config *viper.Viper) (*AuditWriter, error) {
	attempts := config.GetInt("output.pubsub.attempts")
	if attempts < 1 {
		return nil, fmt.Errorf("Output attempts for stdout must be at least 1, %v provided", attempts)
	}
	return NewAuditWriter(&PubSubWriter{}, attempts), nil
}
