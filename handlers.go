package godoauth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/net/context"
)

type Priv uint

const (
	PrivPush    Priv = 1
	PrivPull         = 2
	PrivAll          = 3 // NB: equivlant to (PrivPush | PrivPull)
	PrivIllegal      = 4
)

func (p Priv) Has(q Priv) bool {
	return (p&q == q)
}

func (p Priv) Valid() bool {
	return (PrivPush <= p && p < PrivIllegal)
}

func NewPriv(privilege string) Priv {
	switch privilege {
	case "push":
		return PrivPush
	case "pull":
		return PrivPull
	case "push,pull", "pull,push", "*":
		return PrivPush | PrivPull
	default:
		return PrivIllegal
	}
}

func (p Priv) Actions() []string {
	var result []string
	if p.Has(PrivPush) {
		result = append(result, "push")
	}

	if p.Has(PrivPull) {
		result = append(result, "pull")
	}
	return result
}

// TokenAuthHandler handler for the docker token request
// Docker client will pass the following parameters in the request
//
// service - The name of the service which hosts the resource. (required)
// scope - The resource in question. Can be speficied more time (required)
// account - name of the account. Optional usually get passed only if docker login
type TokenAuthHandler struct {
	// Main config file ... similar as in the server handler
	Config *Config
	// Account name of the user
	Account string
	// Service identifier ... One Auth server may be source of true for different services
	Service string
}

// Scope definition
type Scope struct {
	Type    string // repository
	Name    string // foo/bar
	Actions Priv   // Priv who would guess that ?
}

// UnmarshalText decodes the Scope data from the standard text-form:
// <type>:<name>:<actions>
func (s *Scope) UnmarshalText(b []byte) error {
	split := strings.Split(string(b), ":")
	if len(split) != 3 {
		return fmt.Errorf("malformed scope")
	}

	if split[0] != "repository" {
		return fmt.Errorf("malformed scope: 'repository' not specified")
	}

	p := NewPriv(split[2])
	if !p.Valid() {
		return fmt.Errorf("malformed scope: invalid privilege")
	}

	s.Type = split[0]
	s.Name = split[1]
	s.Actions = p
	return nil
}

// AuthRequest parse the client request
type AuthRequest struct {
	Service  string
	Account  string
	Password string
	Scope    *Scope
}

func actionAllowed(reqscopes *Scope, vuser *UserInfo) *Scope {
	if reqscopes == nil {
		return &Scope{}
	}

	allowedPrivs := vuser.Access[reqscopes.Name]

	if allowedPrivs.Has(reqscopes.Actions) {
		return reqscopes
	}
	if (allowedPrivs & reqscopes.Actions) > 0 {
		return &Scope{
			Type:    "repository",
			Name:    reqscopes.Name,
			Actions: allowedPrivs & reqscopes.Actions,
		}
	}
	return &Scope{}
}

type idKeyType int

var idKey = idKeyType(0)

func logWithID(ctx context.Context, pattern string, vars ...interface{}) {
	id := ctx.Value(idKey)
	vars = append([]interface{}{id}, vars...)
	log.Printf("%d "+pattern, vars...)
}

func (h *TokenAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, idKey, rand.Int31())
	ctx, cancel := context.WithTimeout(ctx, h.Config.HTTP.Timeout)
	defer cancel()

	logWithID(ctx, "GET %v", r.RequestURI)

	authRequest, err := parseRequest(r)
	if err != nil {
		logWithID(ctx, err.Error())
		http.Error(w, err.Error(), err.(*HTTPAuthError).Code)
		return
	}

	// you need at least one of the parameter to be non empty
	// if only account true you authenticate only
	// if only scope true you ask for anonymous priv
	if authRequest.Account == "" && authRequest.Scope == nil {
		err := HTTPBadRequest("malformed scope")
		http.Error(w, err.Error(), err.Code)
		return
	}

	// BUG(dejan) we do not support anonymous images yet
	if authRequest.Account == "" {
		http.Error(w, "Public repos not supported yet", ErrUnauthorized.Code)
		return
	}

	// sometimes can happen that docker client will send only
	// account param without BasicAuth, so we need to send 401 Unauth.
	if authRequest.Account != "" && authRequest.Password == "" {
		http.Error(w, ErrUnauthorized.Error(), ErrUnauthorized.Code)
		return
	}

	userdata, err := h.authAccount(ctx, authRequest)
	if err != nil {
		logWithID(ctx, "Auth failed %s", err)
		http.Error(w, err.Error(), err.(*HTTPAuthError).Code)
		return
	}
	if userdata == nil {
		http.Error(w, "User has no access", http.StatusForbidden)
		return
	}

	grantedActions := actionAllowed(authRequest.Scope, userdata)

	stringToken, err := h.CreateToken(grantedActions, authRequest.Service, authRequest.Account)
	if err != nil {
		logWithID(ctx, "token error %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tokenOutput := struct {
		Token string `json:"token"`
	}{
		Token: stringToken,
	}
	tokenBytes, err := json.Marshal(tokenOutput)
	if err != nil {
		logWithID(ctx, "error marshalling token output: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// All it's ok, so get the good news back
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(tokenBytes)
	if err != nil {
		log.Printf("error writing result to client: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	logWithID(ctx, "Auth granted")
}

func (h *TokenAuthHandler) authAccount(ctx context.Context, authRequest *AuthRequest) (*UserInfo, error) {
	vaultClient := VaultClient{Config: &h.Config.Storage.Vault}
	vuser, err := vaultClient.RetrieveUser(ctx, authRequest.Service, authRequest.Account)
	if err != nil {
		return nil, err
	}
	//		log.Printf("DEBUG %#v", vuser)
	if vuser.Password == authRequest.Password {
		return vuser, nil
	}
	return nil, nil
}

func (h *TokenAuthHandler) CreateToken(scopes *Scope, service, account string) (string, error) {
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

	now := time.Now().Unix()
	token.Claims["exp"] = now + h.Config.Token.Expiration
	token.Claims["nbf"] = now - 1
	token.Claims["iat"] = now
	token.Claims["jti"] = fmt.Sprintf("%d", rand.Int63())

	if scopes.Type != "" {
		token.Claims["access"] = []struct {
			Type, Name string
			Actions    []string
		}{
			{
				scopes.Type,
				scopes.Name,
				scopes.Actions.Actions(),
			},
		}
	}

	f, err := ioutil.ReadFile(h.Config.Token.Key)
	if err != nil {
		return "", err
	}
	return token.SignedString(f)
}

func getService(req *http.Request) (string, error) {
	service := req.FormValue("service")
	if service == "" {
		return "", HTTPBadRequest("missing service from the request.")
	}
	return service, nil
}

// getScopes will check for the scope GET parameter and verify if it's properly
// formated as specified by the Docker Token Specification
//
// format: repository:namespace:privileges
// example: repository:foo/bar:push,read
func getScopes(req *http.Request) (*Scope, error) {
	scope := req.FormValue("scope")
	if scope == "" {
		return nil, nil
	}

	s := &Scope{}
	err := s.UnmarshalText([]byte(scope))
	if err != nil {
		return nil, HTTPBadRequest(err.Error())
	}
	return s, nil
}

func parseRequest(req *http.Request) (*AuthRequest, error) {
	service, err := getService(req)
	if err != nil {
		log.Print(err)
		return nil, err
	}

	account := req.FormValue("account")

	scopes, err := getScopes(req)
	if err != nil {
		return nil, err
	}

	user, pass, haveAuth := req.BasicAuth()
	if haveAuth {
		if account != "" && user != account {
			return nil, HTTPBadRequest("authorization failue. account and user passed are different.")
		}
		account = user
	}

	return &AuthRequest{
		Service:  service,
		Account:  account,
		Password: pass,
		Scope:    scopes,
	}, nil
}
