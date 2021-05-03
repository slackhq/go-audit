package main

import (
	"github.com/spf13/viper"
)

func init() {
	RegisterExtraParser(func(config *viper.Viper) (ExtraParser, error) {
		if config.GetBool("extras.metadata.enabled") {
			mp := NewMetadataParser(config)
			return mp, nil
		}
		return nil, nil
	})
}

type MetadataParser struct {
	pairs map[string]string
}

func NewMetadataParser(config *viper.Viper) *MetadataParser {
	return &MetadataParser{
		pairs: config.GetStringMapString("extras.metadata.pairs"),
	}
}

func (mp MetadataParser) Parse(am *AuditMessage) {
	am.Metadata = mp.pairs
}
