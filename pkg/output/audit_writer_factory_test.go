package output

import (
	"errors"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

type noopWriter struct{ t *testing.T }

func (t *noopWriter) Write(a []byte) (int, error) {
	return 0, nil
}

func testFactory(conf *viper.Viper) (*AuditWriter, error) {
	return NewAuditWriter(&noopWriter{}, 1), nil
}

func secondTestFactory(conf *viper.Viper) (*AuditWriter, error) {
	return nil, errors.New("someerror")
}

func TestRegistrationProcess(t *testing.T) {
	// The factory registered in this test should not show up in the avail
	// writers prior to the call, the register is not called in init
	before := GetAvailableAuditWriters()
	register("test1", testFactory)
	after := GetAvailableAuditWriters()

	assert.NotContains(t, before, "test1")
	assert.Contains(t, after, "test1")

	// already registered should only show one in avail writers
	register("test1", secondTestFactory)
	after = GetAvailableAuditWriters()

	matchedWriterCount := 0
	for _, val := range after {
		if val == "test1" {
			matchedWriterCount++
		}
	}

	assert.Equal(t, matchedWriterCount, 1)
}

func TestCreateAuditWriter(t *testing.T) {
	config := viper.New()

	// invalid
	result, err := CreateAuditWriter("doesnotexist", config)
	assert.NotNil(t, err)
	assert.Nil(t, result)

	register("successtest", testFactory)
	writer, err := CreateAuditWriter("successtest", config)

	assert.NotNil(t, writer)
	assert.Nil(t, err)

	register("errortest", secondTestFactory)
	writer, err = CreateAuditWriter("errortest", config)
	assert.Nil(t, writer)
	assert.NotNil(t, err)
}
