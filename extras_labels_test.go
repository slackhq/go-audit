package main

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestLabelsParser(t *testing.T) {
	pairs := map[string]string{"hello": "world"}

	c := viper.New()
	c.Set("extras.labels.enabled", true)
	c.Set("extras.labels.pairs", pairs)

	am := &AuditMessage{}

	mp := NewLabelsParser(c)
	mp.Parse(am)

	assert.Equal(t, am.Labels, pairs)
}
