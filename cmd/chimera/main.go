package main

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"strings"
)

func main() {
	rootCmd := newRootCmd()

	if err := rootCmd.Execute(); err != nil {
		logrus.WithError(err).Error("command failed")
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "chimera",
		Short: "Chimera CLI",
		// SilenceErrors allows us to explicitly log the error returned from rootCmd below.
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Usage()
		},
	}

	rootCmd.AddCommand(newServeCmd())

	cobra.OnInitialize(func() {
		bindFlags(rootCmd)

		viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
		viper.SetEnvPrefix("CHIMERA")
		viper.AutomaticEnv()
	})

	return rootCmd
}

// Binds all flags as viper values
func bindFlags(cmd *cobra.Command) {
	viper.BindPFlags(cmd.PersistentFlags())
	viper.BindPFlags(cmd.Flags())
	for _, c := range cmd.Commands() {
		bindFlags(c)
	}
}
