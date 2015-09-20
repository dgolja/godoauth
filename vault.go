package godoauth

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
)

type VaultClient struct {
	Config *Vault
}

type VaultUser struct {
	Username string
	Password string
	Access   map[string]Privilege
}

//RetrieveUser simple retrieve option for POC
//BUG(dejan) We need to add some context and potentiall a pool of clients
func (c *VaultClient) RetrieveUser(user string) (*VaultUser, error) {

	config := api.DefaultConfig()
	config.Address = c.Config.Proto + "://" + c.Config.Host + ":" + strconv.Itoa(c.Config.Port)
	fmt.Printf("vault config: %+v\n", config)
	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("error creating client: %v", err)
	}
	client.SetToken(c.Config.AuthToken)
	req := client.NewRequest("GET", "/v1/"+c.Config.Mount+"/"+user)
	resp, err := client.RawRequest(req)
	if err != nil {
		return nil, fmt.Errorf("error calling vault API: %v", err)
	}

	// fmt.Printf("%v\n", resp)
	respData := struct {
		Data struct {
			Access   string `json:"access"`
			Password string `json:"password"`
		} `json:"data"`
	}{}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&respData)
	if err != nil {
		return nil, fmt.Errorf("error parsing JSON response: %v", err)
	}

	accessMap := make(map[string]Privilege)
	semiColonSplit := strings.Split(respData.Data.Access, ";")
	for _, x := range semiColonSplit {
		xx := strings.Split(x, ":")
		if len(xx) != 3 {
			return nil, fmt.Errorf("expected length 3: %v", x)
		}
		accessMap[xx[1]] = NewPrivilege(xx[2])
	}

	return &VaultUser{
		Username: user,
		Password: respData.Data.Password,
		Access:   accessMap,
	}, nil
}
