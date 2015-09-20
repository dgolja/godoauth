package godoauth

import (
	"errors"
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
	PrivilegeAll               = 3 // NB: equivlant to PrivilegePush & PrivilegePull
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

func (h *TokenAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	log.Println("request ", r.RequestURI)
	for k, v := range r.Header {
		log.Println("Header:", k, "Value:", v)
	}

	account := r.FormValue("account")

	authenticated, err := h.authAccount(r, account)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if !authenticated {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	service, err := h.getService(r)
	if err != nil {
		log.Print(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Print(service)

	scopes, err := h.getScopes(r)
	if err != nil {
		fmt.Println(err)
		if account == "" {
			log.Printf("string error %s\n", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} else {
			scopes = &Scope{}
		}
	}
	log.Print(scopes)

	stringToken, err := h.CreateToken(scopes, service, account)
	if err != nil {
		log.Printf("string error %s\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// All it's ok get the good news back
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write([]byte("{\"token\": \"" + stringToken + "\"}"))
}

func (h *TokenAuthHandler) authAccount(req *http.Request, account string) (bool, error) {
	user, pass, haveAuth := req.BasicAuth()
	if haveAuth {
		vaultClient := VaultClient{&h.Config.Storage.Vault}
		vuser, err := vaultClient.RetrieveUser(user)
		if err != nil {
			return false, err
		}
		log.Printf("%#v", vuser)

		if vuser.Username == user && vuser.Password == pass {
			return true, nil
		} else {
			return false, nil
		}
	} else {
		return false, errors.New("Authorization Header Missing")
	}
}

func (h *TokenAuthHandler) getService(req *http.Request) (string, error) {
	service := req.FormValue("service")
	if service == "" {
		return "", errors.New("Failed to retrieve service from the request")
	}
	return service, nil
}

// getScopes will check for the scope GET paramaeter and verify if's properly formated
func (h *TokenAuthHandler) getScopes(req *http.Request) (*Scope, error) {
	scope := req.FormValue("scope")
	if scope == "" {
		return nil, errors.New("missing scope")
	}

	if len(strings.Split(scope, ":")) != 3 {
		return nil, errors.New("malformed scope")
	}

	getscope := strings.Split(scope, ":")
	if getscope[0] != "repository" {
		return nil, errors.New("malformed scope: 'repository' not specified")
	}

	p := NewPrivilege(getscope[2])
	fmt.Println(p, getscope[2])
	if !p.Valid() {
		return nil, errors.New("malformed scope: invalid privilege")
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
