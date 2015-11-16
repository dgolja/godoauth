package godoauth

import (
	"net/http"
	"testing"
)

func TestParseRequest(t *testing.T) {
	req, _ := http.NewRequest("GET", "/wrong", nil)
	_, err := parseRequest(req)
	if err == nil {
		t.Fatalf("Invalid request %s didn't fail", req.URL.RequestURI())
	}

	req, _ = http.NewRequest("GET", "/?account=foo", nil)
	_, err = parseRequest(req)
	if err == nil {
		t.Fatalf("Invalid request %s didn't fail", req.URL.RequestURI())
	}

	req, _ = http.NewRequest("GET", "/?service=registry", nil)
	res, err := parseRequest(req)
	if err != nil {
		t.Fatalf("Valid request %s failed", req.URL.RequestURI())
	}
	if res.Service != "registry" {
		t.Fatalf("Expected service registry, but received %s", res.Service)
	}
	if res.Account != "" {
		t.Fatalf("Expected empty account, but received %s", res.Account)
	}
	if res.Password != "" {
		t.Fatalf("Expected empty password, but received %s", res.Password)
	}
	if res.Scope != nil {
		t.Fatalf("Expected empty scope, but received %v", res.Scope)
	}

	req, _ = http.NewRequest("GET", "/?service=registry?account=foo", nil)
	res, err = parseRequest(req)
	if err != nil {
		t.Fatalf("Valid request %s failed", req.URL.RequestURI())
	}

}

func TestPrivileges(t *testing.T) {

	if !NewPriv("push,pull").Has(PrivPull) {
		t.Fatalf("PrivAll does have PrivPull")
	}

	if !NewPriv("push,pull").Has(PrivPush) {
		t.Fatalf("PrivAll does have PrivPush")
	}

	if NewPriv("push,pull").Has(PrivIllegal) {
		t.Fatalf("PrivAll does not have PrivIllegal")
	}

	if !NewPriv("push,pull").Has(PrivAll) {
		t.Fatalf("PrivAll does have PrivAll")
	}

	if !NewPriv("pull").Has(PrivPull) {
		t.Fatalf("PrivPull does have PrivPull")
	}

	if NewPriv("pull").Has(PrivAll) {
		t.Fatalf("PrivPull does not have PrivAll")
	}

	if NewPriv("pull").Has(PrivPush) {
		t.Fatalf("PrivPull does not have PrivPush")
	}

	if NewPriv("pull").Has(PrivIllegal) {
		t.Fatalf("PrivPull does not have PrivIllegal")
	}

	if !NewPriv("push").Has(PrivPush) {
		t.Fatalf("PrivPush does have PrivPush")
	}

	if NewPriv("push").Has(PrivAll) {
		t.Fatalf("PrivPush does not have PrivAll")
	}

	if NewPriv("push").Has(PrivPull) {
		t.Fatalf("PrivPush does not have PrivPull")
	}

	if NewPriv("push").Has(PrivIllegal) {
		t.Fatalf("PrivPush does not have PrivIllegal")
	}
}

func TestActionAllowed(t *testing.T) {

	accessMap := make(map[string]Priv)
	accessMap["foo/bar"] = PrivAll

	vuser := &UserInfo{
		Username: "foo",
		Password: "bar",
		Access:   accessMap,
	}

	scope := actionAllowed(nil, vuser)
	if scope.Type != "" {
		t.Fatalf("Expected empty type, but received %s failed", scope.Type)
	}

	reqscope := &Scope{
		Type:    "repository",
		Name:    "zala/srot",
		Actions: PrivAll,
	}

	scope = actionAllowed(reqscope, vuser)
	if scope.Name != "" {
		t.Fatalf("Expected empty name, but received %v", scope)
	}

	reqscope = &Scope{
		Type:    "repository",
		Name:    "foo/bar",
		Actions: PrivAll,
	}

	scope = actionAllowed(reqscope, vuser)
	if scope.Name != "foo/bar" || scope.Actions != PrivAll {
		t.Fatalf("Expected foo/bar with privilege All, but received %v", scope)
	}

	reqscope = &Scope{
		Type:    "repository",
		Name:    "foo/bar",
		Actions: PrivPush,
	}

	scope = actionAllowed(reqscope, vuser)
	if scope.Name != "foo/bar" || scope.Actions != PrivPush {
		t.Fatalf("Expected foo/bar with privilege Push, but received %v", scope)
	}

}
