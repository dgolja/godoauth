package main

import (
	"flag"
	"fmt"
	"github.com/n1tr0g/godoauth"
	"os"
	"path/filepath"
)

var (
	version string = "0.0.1"
	commit  string
)

func main() {
	var (
		showVersion bool
		config      godoauth.Configuration
	)

	fs := flag.NewFlagSet("Go Docker Token Auth "+version, flag.ExitOnError)

	currentDir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	confFile := fs.String("config", filepath.Join(currentDir, "config.yaml"), "Go Docker Token Auth Config file")
	listenAddr := fs.String("listen", "tcp://127.0.0.1:8080", "protocol://location for HTTP queries: unix:///tmp/godoauth.sock or tcp://127.0.0.1:8081")
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

	fmt.Printf("Config:\n%+v %s\n", config, *listenAddr)

}
