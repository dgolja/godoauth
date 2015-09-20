package godoauth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/docker/libtrust"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"strings"
)

type Configuration struct {
	Version string     `yaml:"version,omitempty"`
	Log     Log        `yaml:"log,omitempty"`
	Storage Storage    `yaml:"storage,omitempty"`
	Http    ServerConf `yaml:"http"`
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
	Port int    `yaml:"port"`
}

type ServerConf struct {
	Addr    string    `yaml:"addr"`
	Timeout string    `yaml:"timeout"`
	Tls     ServerTls `yaml:"tls"`

	publicKey  libtrust.PublicKey
	privateKey libtrust.PrivateKey
}

type ServerTls struct {
	Certificate string `yaml:"certificate,omitempty"`
	Key         string `yaml:"key,omitempty"`
}

type Token struct {
	Issuer      string `yaml:"issuer"`
	Expiration  int64  `yaml:"expiration"`
	Certificate string `yaml:"certificate,omitempty"`
	Key         string `yaml:"key,omitempty"`

	publicKey  libtrust.PublicKey
	privateKey libtrust.PrivateKey
}

func (c *Configuration) Parse(configurationPath *string) error {

	in, err := ioutil.ReadFile(*configurationPath)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(in, c); err != nil {
		return err
	}
	if c.Token.Certificate != "" && c.Token.Key != "" {
		c.Token.publicKey, c.Token.privateKey, err = c.loadCerts(c.Token.Certificate, c.Token.Key)
		if err != nil {
			return err
		}
	}
	// Sign something dummy to find out which algorithm is used.
	_, sigAlg, err := c.Token.privateKey.Sign(strings.NewReader("whoami"), 0)
	if err != nil {
		return fmt.Errorf("failed to sign: %s", err)
	}
	// check if the library supports this sign algorithm
	if alg := jwt.GetSigningMethod(sigAlg); alg == nil {
		return fmt.Errorf("Not supported sign algorhithem: %s", sigAlg)
	}

	return nil
}

func (c *Configuration) loadCerts(certFile, keyFile string) (pk libtrust.PublicKey, prk libtrust.PrivateKey, err error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return
	}
	x509Cert, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return
	}
	pk, err = libtrust.FromCryptoPublicKey(x509Cert.PublicKey)
	if err != nil {
		return
	}
	prk, err = libtrust.FromCryptoPrivateKey(certificate.PrivateKey)
	return
}
