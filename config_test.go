package godoauth

import (
	//	"gopkg.in/yaml.v2"
	"bytes"
	"reflect"
	"testing"
	"time"
)

var configStruct = Config{
	Version: "0.1",
	Log: Log{
		Level: "info",
		File:  "/tmp/godoauth.log",
	},
	Storage: Storage{
		Vault: Vault{
			Host:      "127.0.0.1",
			Proto:     "http",
			Port:      8200,
			AuthToken: "dbXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXX",
			Timeout:   time.Duration(3 * time.Second),
		},
	},
	HTTP: ServerConf{
		Addr:    ":5002",
		Timeout: "5s",
		TLS: ServerTLS{
			Certificate: "certs/server.pem",
		},
	},
	Token: Token{
		Issuer:      "Token",
		Expiration:  800,
		Key:         "certs/server.key",
		Certificate: "certs/server.pem",
	},
}

// configYamlV0_1 is a Version 0.1 yaml document representing configStruct
var configYamlV0_1 = `
---
#sample config file
version: 0.1
log:
  level: info
  file: /tmp/godoauth.log
storage:
  vault:
    proto: http
    host: 127.0.0.1
    port: 8200
    auth_token: dbXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXX
    timeout: 3s
http:
  timeout: 5s
  addr: :5002
  tls:
    certificate: certs/server.pem
token:
   issuer: Token
   expiration: 800
   certificate: certs/server.pem
   key: certs/server.key
`

// MinConfigYamlV0_1 is a Version 0.1 yaml document representing minimal settings
var MinConfigYamlV0_1 = `
---
#sample config file
version: 0.1
log:
  level: info
storage:
  vault:
    proto: http
    host: 127.0.0.1
    port: 8200
    auth_token: dbXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXX
http:
  addr: :5002
  tls:
    certificate: certs/server.pem
token:
   issuer: Token
   expiration: 800
   certificate: certs/server.pem
   key: certs/server.key
`

// MinConfigYamlV0_1 is a Version 0.1 yaml document representing minimal settings
var BrokenVaultYamlV0_1 = `
---
#sample config file
version: 0.1
log:
  level: info
storage:
  vault:
    proto: http
    host: 127.0.0.1
    port: port
    auth_token: dbXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXX
http:
  addr: :5002
  tls:
    certificate: certs/server.pem
token:
   issuer: Token
   expiration: 800
   certificate: certs/server.pem
   key: certs/server.key
`

// TestConfigParse validates that configYamlV0_1 can be parsed into a struct
// matching configStruct
func TestConfigParse(t *testing.T) {
	var config Config
	err := config.Parse(bytes.NewReader([]byte(configYamlV0_1)))
	if err != nil {
		t.Fatalf("unexpected error while parsing config file: %s", err)
	}
	if !reflect.DeepEqual(config, configStruct) {
		t.Fatalf("unexpected error while comparing config files\n%v\n%v", config, configStruct)
	}
}

// TestParseIncomplete validates if broken config files file the parser
func TestParseIncomplete(t *testing.T) {
	var config Config
	incompleteConfigYaml := "version: 0.1"
	err := config.Parse(bytes.NewReader([]byte(incompleteConfigYaml)))
	if err == nil {
		t.Fatalf("Expected error while parsing config file: %s", incompleteConfigYaml)
	}
}

// TestParseIncomplete validates if broken config files file the parser
func TestParseMinimalConfig(t *testing.T) {
	var config Config
	err := config.Parse(bytes.NewReader([]byte(MinConfigYamlV0_1)))
	if err != nil {
		t.Fatalf("unexpected error while parsing config file: %s", err)
	}
	// TODO(dejan): Fix the default value setting for Timeout.
	if config.Storage.Vault.Timeout != time.Duration(3 * time.Second) {
		t.Fatalf("unexpected default Vault timeout value %s", config.Storage.Vault.Timeout)
	}
	if config.HTTP.Timeout != "5s" {
		t.Fatalf("unexpected default HTTP timeout value %s", config.Storage.Vault.Timeout)
	}
}

// TestParseIncomplete validates if broken config files file the parser
func TestParseBrokenVaultConfig(t *testing.T) {
	var config Config
	err := config.Parse(bytes.NewReader([]byte(BrokenVaultYamlV0_1)))
	if err == nil {
		t.Fatal("Expected error while parsing config ")
	}
}
