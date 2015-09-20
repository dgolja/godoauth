package godoauth

import (
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Privilege uint

const (
	PrivilegeIllegal Privilege = 0
	PrivilegePush              = 1
	PrivilegePull              = 2
	PrivilegeAll               = 3 // NB: equivlant to (PrivilegePush | PrivilegePull)
)

func (p Privilege) Has(q Privilege) bool {
	return (p&q == q)
}

func (p Privilege) Valid() bool {
	return (PrivilegeIllegal < p && p <= PrivilegeAll)
}

func NewPrivilege(privilege string) Privilege {
	switch privilege {
	case "push":
		return PrivilegePush
	case "pull":
		return PrivilegePull
	case "push,pull", "pull,push", "*":
		return PrivilegePush | PrivilegePull
	default:
		return PrivilegeIllegal
	}
}

func (p Privilege) Actions() []string {
	result := make([]string, 0)
	if p.Has(PrivilegePush) {
		result = append(result, "push")
	}

	if p.Has(PrivilegePull) {
		result = append(result, "pull")
	}
	return result
}

// Holds all information required for the handler to work
type TokenAuthHandler struct {
	// The HTTP client maight be shared across multiple handlers, saving TCP connections
	// we will use that later on for valut
	Client *http.Client
	// Main config file ... similar as in the server handler
	Config *Configuration
	// Account name of the user
	Account string
	// Service identifier ... One Auth server may be source of true for different services
	Service string
}

// Scope definition
type Scope struct {
	Type    string    // repository
	Name    string    // foo/bat
	Actions Privilege // Privilege who would guess that ?
}

func scopeAllowed(reqscopes *Scope, vuser *VaultUser) *Scope {

	allowedPrivileges := vuser.Access[reqscopes.Name]
	if reqscopes.Type == "" || allowedPrivileges == PrivilegeIllegal {
		return &Scope{}
	}

	if allowedPrivileges.Has(reqscopes.Actions) {
		return reqscopes
	} else {
		return &Scope{"repository", reqscopes.Name, allowedPrivileges}
	}
}

func (h *TokenAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	log.Println("GET", r.RequestURI)
	// for k, v := range r.Header {
	// 	log.Println("Header:", k, "Value:", v)
	// }

	service, err := h.getService(r)
	if err != nil {
		log.Print(err)
		http.Error(w, err.Error(), err.(*HTTPAuthError).Code)
		return
	}
	//	log.Print("DEBUG",service)

	account := r.FormValue("account")
	scopes, err := h.getScopes(r)
	if err != nil {
		// log.Printf("DEBUG getScopes error %s\n", err)
		if account == "" {
			http.Error(w, err.Error(), err.(*HTTPAuthError).Code)
			return
		} else {
			scopes = &Scope{}
		}
	}
	// log.Printf("%#v", scopes)

	userdata, err := h.authAccount(r, account)
	if err != nil {
		http.Error(w, err.Error(), err.(*HTTPAuthError).Code)
		return
	}
	if userdata == nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	grantedActions := scopeAllowed(scopes, userdata)

	stringToken, err := h.CreateToken(grantedActions, service, account)
	if err != nil {
		log.Printf("token error %s\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// All it's ok, so get the good news back
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write([]byte("{\"token\": \"" + stringToken + "\"}"))
}

func (h *TokenAuthHandler) authAccount(req *http.Request, account string) (*VaultUser, error) {
	user, pass, haveAuth := req.BasicAuth()
	if account != "" && user != account {
		return nil, HTTPBadRequest("authoziration failue. account and user passed are diffrent.")
	}
	if haveAuth {
		vaultClient := VaultClient{&h.Config.Storage.Vault}
		vuser, err := vaultClient.RetrieveUser(req.FormValue("service"), user)
		if err != nil {
			return nil, err
		}
		log.Printf("DEBUG %#v", vuser)

		if vuser.Username == user && vuser.Password == pass {
			return vuser, nil
		} else {
			return nil, nil
		}
	} else {
		return nil, ErrUnauthorized
	}
}

func (h *TokenAuthHandler) getService(req *http.Request) (string, error) {
	service := req.FormValue("service")
	if service == "" {
		return "", HTTPBadRequest("missing service from the request.")
	}
	return service, nil
}

// getScopes will check for the scope GET paramaeter and verify if's properly formated
func (h *TokenAuthHandler) getScopes(req *http.Request) (*Scope, error) {
	scope := req.FormValue("scope")
	if scope == "" {
		return nil, HTTPBadRequest("missing scope")
	}

	if len(strings.Split(scope, ":")) != 3 {
		return nil, HTTPBadRequest("malformed scope")
	}

	getscope := strings.Split(scope, ":")
	if getscope[0] != "repository" {
		return nil, HTTPBadRequest("malformed scope: 'repository' not specified")
	}

	p := NewPrivilege(getscope[2])
	if !p.Valid() {
		return nil, HTTPBadRequest("malformed scope: invalid privilege")
	}

	return &Scope{
		getscope[0],
		getscope[1],
		p,
	}, nil
}

func (h *TokenAuthHandler) CreateToken(scopes *Scope, service, account string) (tokenString string, err error) {
	now := time.Now().Unix()

	// Sign something dummy to find out which algorithm is used.
	_, sigAlg, err := h.Config.Token.privateKey.Sign(strings.NewReader("whoami"), 0)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %s", err)
	}

	token := jwt.New(jwt.GetSigningMethod(sigAlg))
	token.Header["kid"] = h.Config.Token.publicKey.KeyID()

	token.Claims["iss"] = h.Config.Token.Issuer
	token.Claims["sub"] = account
	token.Claims["aud"] = service
	token.Claims["exp"] = now + h.Config.Token.Expiration
	token.Claims["nbf"] = now - 1
	token.Claims["iat"] = now
	token.Claims["jti"] = fmt.Sprintf("%d", rand.Int63())
	if scopes.Type != "" {
		token.Claims["access"] = []struct {
			Type, Name string
			Actions    []string
		}{{
			scopes.Type,
			scopes.Name,
			scopes.Actions.Actions(),
		},
		}
	}
	f, _ := ioutil.ReadFile(h.Config.Token.Key)
	tokenString, err = token.SignedString(f)
	return
}
