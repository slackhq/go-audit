package main

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestMetadataParser(t *testing.T) {
	pairs := map[string]string{"hello": "world"}

	c := viper.New()
	c.Set("extras.metadata.enabled", true)
	c.Set("extras.metadata.pairs", pairs)

	am := &AuditMessage{}

	mp := NewMetadataParser(c)
	mp.Parse(am)

	assert.Equal(t, am.Metadata, pairs)
}
