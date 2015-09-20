package godoauth

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// define repository access states
const (
	ILLEGAL = iota
	PUSH
	PULL
	ALL_PRIV
)

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
	Type    string
	Name    string
	Actions []string
}

func (h *TokenAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	var scopes *Scope

	log.Println("request ", r.RequestURI)
	for k, v := range r.Header {
		log.Println("Header:", k, "Value:", v)
	}

	account := r.FormValue("account")

	h.Account = account
	authenticated, err := h.authAccount(r, account)
	if err != nil || !authenticated {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	service, err := h.getService(r)
	if err != nil {
		log.Print(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.Service = service
	log.Print(service)

	scopes, err = h.getScopes(r)
	if err != nil {
		if account == "" {
			log.Printf("string error %s\n", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} else {
			scopes = &Scope{}
		}
	}
	log.Print(scopes)

	stringToken, err := h.CreateToken(scopes)
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
	// BUG(dejan) always true for foo:bar until fully developed
	user, pass, haveAuth := req.BasicAuth()
	if haveAuth {
		if user == "foo" && pass == "bar" {
			return true, nil
		} else {
			return false, errors.New("Wrong credentials")
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
		return nil, errors.New("Scope is missing.")
	}
	if len(strings.Split(scope, ":")) != 3 {
		return nil, errors.New("Scope is malformed.")
	}
	getscope := strings.Split(scope, ":")
	if getscope[0] != "repository" || validPrivilege(getscope[2]) == ILLEGAL {
		return nil, errors.New("Scope is malformed..")
	}
	return &Scope{getscope[0], getscope[1], strings.Split(getscope[2], ",")}, nil
}

func (h *TokenAuthHandler) CreateToken(scopes *Scope) (tokenString string, err error) {
	now := time.Now().Unix()

	// Sign something dummy to find out which algorithm is used.
	_, sigAlg, err := h.Config.Token.privateKey.Sign(strings.NewReader("whoami"), 0)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %s", err)
	}

	token := jwt.New(jwt.GetSigningMethod(sigAlg))
	token.Header["kid"] = h.Config.Token.publicKey.KeyID()

	token.Claims["iss"] = h.Config.Token.Issuer
	token.Claims["sub"] = h.Account
	token.Claims["aud"] = h.Service
	token.Claims["exp"] = now + h.Config.Token.Expiration
	token.Claims["nbf"] = now - 1
	token.Claims["iat"] = now
	token.Claims["jti"] = fmt.Sprintf("%d", rand.Int63())
	if scopes.Type != "" {
		token.Claims["access"] = []Scope{*scopes}
	}
	f, _ := ioutil.ReadFile(h.Config.Token.Key)
	tokenString, err = token.SignedString(f)
	return
}

func validPrivilege(privilege string) uint {
	switch privilege {
	case "push":
		return PUSH
	case "pull":
		return PULL
	case "push,pull", "pull,push":
		return ALL_PRIV
	default:
		return ILLEGAL
	}
}
