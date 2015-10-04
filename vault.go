package godoauth

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

type VaultClient struct {
	Config *Vault
}

type VaultUser struct {
	Username string
	Password string
	Access   map[string]Priv
}

// getClient create and configure vault client
func (c *VaultClient) getClient() (*vaultapi.Client, error) {
	timeout, _ := time.ParseDuration(c.Config.Timeout)
	config := &vaultapi.Config{
		Address: c.Config.Proto + "://" + c.Config.Host + ":" + strconv.Itoa(c.Config.Port),
		HttpClient: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return errors.New("redirect")
			},
			Timeout: timeout,
		},
	}

	cl, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, err
	}

	cl.SetToken(c.Config.AuthToken)
	return cl, nil

}

//RetrieveUser retrieve username/password/acl from Vault
//BUG(dejan) We need to add some context and potentiall a pool of clients
func (c *VaultClient) RetrieveUser(namespace, user string) (*VaultUser, *HTTPAuthError) {

	client, err := c.getClient()
	if err != nil {
		log.Printf("error creating client: %v", err)
		return nil, ErrInternal
	}
	url := "/v1/" + namespace + "/" + user
	req := client.NewRequest("GET", url)
	resp, err := client.RawRequest(req)
	if err != nil {
		//log.Printf("DEBUG error calling vault API - %v", err)
		if resp != nil {
			log.Printf("error while retrieving vault data: %s with code: %d", url, resp.StatusCode)
			// that means we don't have access to this resource in vault
			// so we should log an error internally but responde to the client
			// that he has no access
			switch resp.StatusCode {
			case 403:
				log.Print("DEBUG error vault token does not have enough permissions")
				return nil, ErrInternal
			case 404:
				return nil, ErrForbidden
			default:
				return nil, NewHTTPError(err.Error(), resp.StatusCode)
			}
		}
		log.Print(err)
		return nil, ErrInternal
	}

	// fmt.Printf("%v\n", resp)
	respData := struct {
		Data struct {
			Access   string `json:"access"`
			Password string `json:"password"`
		} `json:"data"`
	}{}

	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&respData)
	if err != nil {
		log.Printf("error parsing JSON response: %v", err)
		return nil, ErrInternal
	}

	accessMap := make(map[string]Priv)
	semiColonSplit := strings.Split(respData.Data.Access, ";")
	for _, x := range semiColonSplit {
		xx := strings.Split(x, ":")
		if len(xx) != 3 {
			log.Printf("expected length 3: %v", err)
			return nil, ErrInternal
		}
		accessMap[xx[1]] = NewPriv(xx[2])
	}

	return &VaultUser{
		Username: user,
		Password: respData.Data.Password,
		Access:   accessMap,
	}, nil
}
