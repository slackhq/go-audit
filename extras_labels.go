package main

import (
	"github.com/spf13/viper"
)

func init() {
	RegisterExtraParser(func(config *viper.Viper) (ExtraParser, error) {
		if config.GetBool("extras.labels.enabled") {
			mp := NewLabelsParser(config)
			return mp, nil
		}
		return nil, nil
	})
}

type LabelsParser struct {
	pairs map[string]string
}

func NewLabelsParser(config *viper.Viper) *LabelsParser {
	return &LabelsParser{
		pairs: config.GetStringMapString("extras.labels.pairs"),
	}
}

func (mp LabelsParser) Parse(am *AuditMessage) {
	am.Labels = mp.pairs
}
