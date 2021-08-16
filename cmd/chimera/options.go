package main

import (
	"github.com/spf13/viper"
)

type ServerOptions struct {
	Addr          string
	AppsConfig    string `mapstructure:"apps-config"`
	CacheDriver   string `mapstructure:"cache-driver"`
	CacheExpiry   string `mapstructure:"cache-expiration"`
	RedisAddress  string `mapstructure:"redis-address"`
	RedisPassword string `mapstructure:"redis-password"`
	RedisDatabase int    `mapstructure:"redis-database"`
	LogLevel      string `mapstructure:"log-level"`
}

func NewFlagOptions() ServerOptions {
	opts := ServerOptions{}

	err := viper.Unmarshal(&opts)
	if err != nil {
		panic(err)
	}

	return opts
}
