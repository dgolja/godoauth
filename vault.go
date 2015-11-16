package godoauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"golang.org/x/net/context"
	"golang.org/x/net/context/ctxhttp"
)

type VaultClient struct {
	Config *Vault
}

var errRedirect = errors.New("redirect")

// getData connect to vault backends and sends a request
// about the user and return the http.Response with the content
//
// If running vault in a HA mode you may need to follow the first redirect
// to get the data from the leader
func (c *VaultClient) getData(ctx context.Context, namespace, user string) (*http.Response, error) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 2 {
				return errRedirect
			}
			return nil
		},
		Timeout: c.Config.Timeout,
	}

	url := fmt.Sprintf("%s/v1/%s/%s", c.Config.HostURL(), namespace, user)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating Vault API request: %v", err)
	}
	req.Header.Set("X-Vault-Token", c.Config.AuthToken)
	return ctxhttp.Do(ctx, client, req)
}

//RetrieveUser retrieve username/password/acl from Vault
//BUG(dejan) We need to add some context and potentiall a pool of clients
func (c *VaultClient) RetrieveUser(ctx context.Context, namespace, user string) (*UserInfo, *HTTPAuthError) {
	resp, err := c.getData(ctx, namespace, user)
	if err != nil {
		log.Printf("%d error while communicating with vault server %s", ctx.Value("id"), err)
		return nil, ErrInternal
	}

	//log.Printf("DEBUG error calling vault API - %v", err)
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusForbidden:
			log.Print("DEBUG error vault token does not have enough permissions")
			return nil, ErrInternal
		case http.StatusNotFound:
			return nil, ErrForbidden
		default:
			return nil, NewHTTPError(err.Error(), resp.StatusCode)
		}
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
		log.Printf("%d error parsing JSON response: %v", ctx.Value("id"), err)
		return nil, ErrInternal
	}

	accessMap := make(map[string]Priv)
	semiColonSplit := strings.Split(respData.Data.Access, ";")
	for _, x := range semiColonSplit {
		xx := strings.Split(x, ":")
		if len(xx) != 3 {
			log.Printf("%d expected length 3: %v", ctx.Value("id"), err)
			return nil, ErrInternal
		}
		accessMap[xx[1]] = NewPriv(xx[2])
	}

	return &UserInfo{
		Username: user,
		Password: respData.Data.Password,
		Access:   accessMap,
	}, nil
}
