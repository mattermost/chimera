package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mattermost/chimera/internal/api"
	"github.com/mattermost/chimera/internal/cache"
	"github.com/mattermost/chimera/internal/oauthapps"
	"github.com/mattermost/chimera/internal/util"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Starts OAuth Hub server",
		// SilenceErrors allows us to explicitly log the error returned from rootCmd below.
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := NewFlagOptions()
			return runServer(cfg)
		},
	}

	cmd.Flags().Int("port", 9876, "Port on which server should be listening.")
	cmd.Flags().String("address", "", "External address of Chimera service.")
	cmd.Flags().String("apps-config", "apps-config.json", "Path to the file containing OAuth apps configuration.")
	cmd.Flags().String("cache-driver", "inMemory", "Cache driver to be used by application, one of: inMemory, redis.")
	cmd.Flags().String("cache-expiration", "10m", "Cache expiry time.")
	cmd.Flags().String("redis-address", "localhost:6379", "Redis server address (required if cache-driver is redis).")
	cmd.Flags().String("redis-password", "", "Redis server password.")
	cmd.Flags().Int("redis-database", 0, "Redis database.")
	cmd.Flags().String("confirmation-template-path", "html/confirm-auth-form.html", "HTML template for authorization confirmation form.")
	cmd.Flags().String("cancel-page-path", "html/cancel-auth.html", "HTML page displayed when canceling authorization.")
	cmd.Flags().String("csrf-secret", "dSgVkYp3s6v9y$B?E(H+MbQeThWmZq4t", "32 byte secret used for generating CSRF tokens.")
	cmd.Flags().String("log-level", "info", "Log level used by Chimera.")

	return cmd
}

func runServer(opts ServerOptions) error {
	instance := util.NewID()

	logLevel, err := logrus.ParseLevel(opts.LogLevel)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to set log level to %q, defaulting to info", opts.LogLevel)
		logLevel = logrus.InfoLevel
	}
	logrus.SetLevel(logLevel)

	logger := logrus.WithField("instance", instance)
	logger.Logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	logger.Infof("Starting Chimera on port: %d", opts.Port)

	if opts.Address == "" {
		opts.Address = fmt.Sprintf("http://localhost:%d", opts.Port)
	}
	logger.Infof("Chimera eternal address: %s", opts.Address)

	appsConfig, err := oauthapps.NewAppsConfigFromFile(opts.AppsConfig)
	if err != nil {
		return errors.Wrap(err, "failed to read oauth apps config")
	}

	err = appsConfig.Validate()
	if err != nil {
		return errors.Wrap(err, "invalid configuration")
	}

	stateCache, err := prepareCache(opts)
	if err != nil {
		return errors.Wrap(err, "failed to initialize state cache")
	}

	apps, err := api.OAuthAppsFromConfig(appsConfig.Apps, opts.Address)
	if err != nil {
		return errors.Wrap(err, "failed to process OAuth apps config")
	}

	config := api.Config{
		BaseURL:                  opts.Address,
		ConfirmationTemplatePath: opts.ConfirmationTemplatePath,
		CancelPagePath:           opts.CancelPagePath,
		CSRFSecret:               []byte(opts.CSRFSecret),
	}

	apiRouter, err := api.RegisterAPI(&api.Context{Logger: logger}, apps, stateCache, config)
	if err != nil {
		return errors.Wrap(err, "failed to register API")
	}

	srv := &http.Server{
		Addr:           fmt.Sprintf(":%d", opts.Port),
		Handler:        apiRouter,
		ReadTimeout:    180 * time.Second,
		WriteTimeout:   180 * time.Second,
		IdleTimeout:    time.Second * 180,
		MaxHeaderBytes: 1 << 20,
		ErrorLog:       log.New(&logrusWriter{logger: logger}, "", 0),
	}

	go func() {
		logger.WithField("addr", srv.Addr).Info("Listening")
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Error("Failed to listen and serve")
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	sig := <-c
	logger.WithField("shutdown-signal", sig.String()).Info("Shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = srv.Shutdown(ctx)
	if err != nil {
		logger.WithError(err).Error("Failed to shut down gracefully")
	}

	return nil
}

func prepareCache(opts ServerOptions) (api.StateCache, error) {
	expiration, err := time.ParseDuration(opts.CacheExpiry)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse cache expiry to duration")
	}

	switch strings.ToLower(opts.CacheDriver) {
	case cache.InMemoryDriver:
		return cache.NewInMemoryCache(expiration), nil
	case cache.RedisDriver:
		return cache.NewRedisCache(cache.RedisConfig{
			Address:  opts.RedisAddress,
			Password: opts.RedisPassword,
			DB:       opts.RedisDatabase,
		}, expiration)
	}

	return nil, fmt.Errorf("unsuported cache driver %q", opts.CacheDriver)
}
