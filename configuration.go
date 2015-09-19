package godoauth

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type Configuration struct {
	Version string     `yaml:"version,omitempty"`
	Log     Log        `yaml:"log,omitempty"`
	Storage Storage    `yaml:"storage,omitempty"`
	Server  ServerConf `yaml:"http"`
	Token   Token      `yaml:"token"`
}

type Log struct {
	Level string `yaml:"level,omitempty"`
	File  string `yaml:"file,omitempty"`
}

type Storage struct {
	Vault Vault `yaml:"vault"`
}

type Vault struct {
	Host string `yaml:"host"`
	Port int    `yaml:port"`
}

type ServerConf struct {
	Addr string    `yaml:"addr"`
	Tls  ServerTls `yaml:"tls"`
}

type ServerTls struct {
	Certificate string   `yaml:certificate`
	Key         string   `yaml:"key"`
	ClientCas   []string `yaml:"clientcas"`
}

type Token struct {
	Issuer     string `yaml:issuer`
	Expiration int    `yaml:expiration`
}

func (c *Configuration) Parse(configurationPath *string) error {

	in, err := ioutil.ReadFile(*configurationPath)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(in, c); err != nil {
		return err
	}
	return nil
}
