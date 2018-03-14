package output

import (
	"errors"
	"fmt"
	"strings"

	"github.com/pantheon-systems/go-audit/pkg/slog"
	"github.com/spf13/viper"
)

type AuditWriterFactory func(conf *viper.Viper) (*AuditWriter, error)

var auditWriterFactories = make(map[string]AuditWriterFactory)

// register adds the audit writer type to the factory
// this method is internal to this package and is used
// by passing in the constructor (factory method) in
// with a string as the key. This is done in the init
// function of the file, thus creating self-registering
// output audit writer factories
func register(name string, factory AuditWriterFactory) {
	if factory == nil {
		slog.Error.Fatalf("Audit writer factory %s does not exist.", name)
	}
	_, registered := auditWriterFactories[name]
	if registered {
		slog.Info.Printf("Audit writer factory %s already registered. Ignoring.", name)
		return
	}

	auditWriterFactories[name] = factory
}

// CreateAuditWriter creates an audit writer with the type specified by the name, the
// viper config is passed down to the audit writer factory method.
// It returns an audit writer or an error
func CreateAuditWriter(auditWriterName string, config *viper.Viper) (*AuditWriter, error) {
	auditWriterFactory, ok := auditWriterFactories[auditWriterName]
	if !ok {
		availableAuditWriters := GetAvailableAuditWriters()
		return nil, errors.New(fmt.Sprintf("Invalid audit writer name. Must be one of: %s", strings.Join(availableAuditWriters, ", ")))
	}

	// Run the factory with the configuration.
	return auditWriterFactory(config)
}

// GetAvailableAuditWriters returns an array of audit writer names as strings
func GetAvailableAuditWriters() []string {
	availableAuditWriters := make([]string, len(auditWriterFactories))
	for k, _ := range auditWriterFactories {
		availableAuditWriters = append(availableAuditWriters, k)
	}
	return availableAuditWriters
}
