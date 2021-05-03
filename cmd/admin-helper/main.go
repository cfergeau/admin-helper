package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var Version = "dev"

func main() {
	commands := []*cobra.Command{
		Add,
		Remove,
		Clean,
		Contains,
	}

	rootCmd := &cobra.Command{
		Use:          "admin-helper",
		Version:      Version,
		SilenceUsage: true,
	}

	rootCmd.AddCommand(commands...)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
