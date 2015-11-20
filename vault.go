package godoauth

import (
	"encoding/json"
	"errors"
	"fmt"
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
	ctx, _ = context.WithTimeout(ctx, c.Config.Timeout)
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 2 {
				return errRedirect
			}
			return nil
		},
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
func (c *VaultClient) RetrieveUser(ctx context.Context, namespace, user string) (*UserInfo, error) {
	resp, err := c.getData(ctx, namespace, user)
	if err != nil {
		logWithID(ctx, "error while communicating with vault server: %v", err)
		return nil, ErrInternal
	}

	switch resp.StatusCode {
	case http.StatusOK:
		break

	case http.StatusForbidden:
		logWithID(ctx, "DEBUG error vault token does not have enough permissions")
		return nil, ErrInternal

	case http.StatusNotFound:
		return nil, ErrForbidden

	default:
		return nil, NewHTTPError(err.Error(), resp.StatusCode)
	}

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
		logWithID(ctx, "error parsing JSON response: %v", err)
		return nil, ErrInternal
	}

	accessMap := make(map[string]Priv)
	semiColonSplit := strings.Split(respData.Data.Access, ";")
	for _, x := range semiColonSplit {
		xx := strings.Split(x, ":")
		if len(xx) != 3 {
			logWithID(ctx, "expected length 3: %v", err)
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
