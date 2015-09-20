package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/n1tr0g/godoauth"
)

var (
	name    string = "Go Docker Token Authenticator - godoauth"
	version string = "0.0.1"
	commit  string
)

func main() {
	var (
		showVersion bool
		config      godoauth.Configuration
		server      *godoauth.Server
	)

	fs := flag.NewFlagSet("Go Docker Token Auth "+version, flag.ExitOnError)

	currentDir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	confFile := fs.String("config", filepath.Join(currentDir, "config.yaml"), "Go Docker Token Auth Config file")
	fs.BoolVar(&showVersion, "version", false, "show the version and exit")

	fs.Parse(os.Args[1:])

	if showVersion {
		fmt.Fprintln(os.Stderr, os.Args[0], version)
		return
	}

	if err := config.Parse(confFile); err != nil {
		fmt.Fprintln(os.Stderr, "Error: ", err)
		os.Exit(1)
	}

	fmt.Printf("Starting %s version: %s\n", name, version)

	server, err := godoauth.NewServer(&config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error while creating new server: ", err)
		os.Exit(1)
	}
	server.Start()

	// waiting for a termination signal to clean up
	interruptChan := make(chan os.Signal)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	<-interruptChan
}
