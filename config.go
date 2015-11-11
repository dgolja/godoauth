package godoauth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/docker/libtrust"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Version string     `yaml:"version,omitempty"`
	Log     Log        `yaml:"log,omitempty"`
	Storage Storage    `yaml:"storage,omitempty"`
	HTTP    ServerConf `yaml:"http"`
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
	Host      string        `yaml:"host"`
	Port      int           `yaml:"port"`
	AuthToken string        `yaml:"auth_token"`
	Proto     string        `yaml:"proto"`
	Timeout   time.Duration `yaml:"timeout,omitempty"`
}

func (v Vault) HostURL() string {
	return fmt.Sprintf("%s://%s:%d", v.Proto, v.Host, v.Proto)
}

type Duration time.Duration

// TODO(dejan): Setup default value when empty
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

type ServerConf struct {
	Addr    string    `yaml:"addr"`
	Timeout string    `yaml:"timeout"`
	TLS     ServerTLS `yaml:"tls"`

	publicKey  libtrust.PublicKey
	privateKey libtrust.PrivateKey
}

type ServerTLS struct {
	Certificate string `yaml:"certificate,omitempty"`
	Key         string `yaml:"key,omitempty"`
}

type Token struct {
	Issuer      string `yaml:"issuer"`
	Expiration  int64  `yaml:"expiration"`
	Certificate string `yaml:"certificate"`
	Key         string `yaml:"key"`

	publicKey  libtrust.PublicKey
	privateKey libtrust.PrivateKey
}

func (c *Config) LoadFromFile(path string) error {
	fp, err := os.Open(path)
	if err != nil {
		return err
	}
	return c.Parse(fp)
}

func (c *Config) Parse(rd io.Reader) error {
	in, err := ioutil.ReadAll(rd)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(in, c)
	if err != nil {
		return err
	}

	if c.Token.Certificate == "" || c.Token.Key == "" {
		return fmt.Errorf("Missing Certificate or Key for the Token definition")
	}

	_, err = url.Parse(c.Storage.Vault.Proto + "://" + c.Storage.Vault.Host + ":" + strconv.Itoa(c.Storage.Vault.Port))
	if err != nil {
		return err
	}

	if c.HTTP.Timeout == "" {
		c.HTTP.Timeout = "5s"
	} else {
		if _, err := time.ParseDuration(c.HTTP.Timeout); err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) LoadCerts() error {
	var err error

	c.Token.publicKey, c.Token.privateKey, err = c.loadCerts(c.Token.Certificate, c.Token.Key)
	if err != nil {
		return err
	}
	// Sign something dummy to find out which algorithm is used.
	_, sigAlg, err := c.Token.privateKey.Sign(strings.NewReader("whoami"), 0)
	if err != nil {
		return fmt.Errorf("failed to sign: %s", err)
	}
	// check if the library supports this sign algorithm
	if alg := jwt.GetSigningMethod(sigAlg); alg == nil {
		return fmt.Errorf("signing algorithm not supported: %s", sigAlg)
	}
	return nil
}

func (c *Config) loadCerts(certFile, keyFile string) (pk libtrust.PublicKey, prk libtrust.PrivateKey, err error) {
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
