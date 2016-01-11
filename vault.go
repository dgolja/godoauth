package godoauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
		Transport: &http.Transport{MaxIdleConnsPerHost: c.Config.Pool},
	}

	url := fmt.Sprintf("%s/v1/%s/%s", c.Config.HostURL(), namespace, user)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating Vault API request: %v", err)
	}
	req.Header.Set("X-Vault-Token", c.Config.AuthToken)
	return ctxhttp.Do(ctx, client, req)
}

func (c *VaultClient) UnmarshalText(r io.Reader) (*UserInfo, error) {

	respData := struct {
		Data struct {
			Access   string `json:"access"`
			Password string `json:"password"`
		} `json:"data"`
	}{}

	dec := json.NewDecoder(r)

	var err error
	err = dec.Decode(&respData)
	if err != nil {
		return nil, ErrInternal
	}

	accessMap := make(map[string]Priv)
	semiColonSplit := strings.Split(respData.Data.Access, ";")
	for _, x := range semiColonSplit {
		xx := strings.Split(x, ":")
		if len(xx) != 3 {
			return nil, NewHTTPError("Wrong access format", http.StatusInternalServerError)
		}
		accessMap[xx[1]] = NewPriv(xx[2])
	}

	return &UserInfo{
		Password: respData.Data.Password,
		Access:   accessMap,
	}, nil
}

//RetrieveUser retrieve username/password/acl from Vault
func (c *VaultClient) RetrieveUser(ctx context.Context, namespace, user string) (*UserInfo, error) {
	resp, err := c.getData(ctx, namespace, user)
	if err != nil {
		logWithID(ctx, "error while communicating with vault server: %v", err)
		return nil, ErrInternal
	}

	defer resp.Body.Close()

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

	userInfo, err := c.UnmarshalText(resp.Body)
	if err != nil {
		logWithID(ctx, "Error while unmarhsaling vault response: %v", err)
	}
	userInfo.Username = user
	return userInfo, err
}
