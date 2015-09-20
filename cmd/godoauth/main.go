package main

import (
	"flag"
	"fmt"
	"github.com/n1tr0g/godoauth"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
)

var (
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

	fmt.Printf("Config:\n%+v\n", config)

	server, err := godoauth.NewServer(&config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error while creating new server: ", err)
		os.Exit(1)
	}

	// Set parallelism.
	runtime.GOMAXPROCS(runtime.NumCPU())
	fmt.Fprintf(os.Stdout, "GOMAXPROCS set to %d\n", runtime.GOMAXPROCS(0))

	server.Start()

	// waiting for a termination signal to clean up
	interruptChan := make(chan os.Signal)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	<-interruptChan

}
