package main

import (
	"github.com/spf13/viper"
)

type ServerOptions struct {
	Addr                     string
	AppsConfig               string `mapstructure:"apps-config"`
	CacheDriver              string `mapstructure:"cache-driver"`
	CacheExpiry              string `mapstructure:"cache-expiration"`
	RedisAddress             string `mapstructure:"redis-address"`
	RedisPassword            string `mapstructure:"redis-password"`
	RedisDatabase            int    `mapstructure:"redis-database"`
	ConfirmationTemplatePath string `mapstructure:"confirmation-template-path"`
	CancelPagePath           string `mapstructure:"cancel-page-path"`
	CSRFSecret           string `mapstructure:"csrf-secret"`
	LogLevel                 string `mapstructure:"log-level"`
}

func NewFlagOptions() ServerOptions {
	opts := ServerOptions{}

	err := viper.Unmarshal(&opts)
	if err != nil {
		panic(err)
	}

	return opts
}
