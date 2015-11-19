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

	for p := 1; p < 4; p++ {
		if !NewPriv("push,pull").Has(Priv(p)) {
			t.Fatalf("push,pull does have %s", Priv(p).Actions())
		}
	}

	if NewPriv("push,pull").Has(PrivIllegal) {
		t.Fatalf("PrivAll does not have PrivIllegal")
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

func TestUnmarshalScopeText(t *testing.T) {
	invalidFormats := []string{
		"something",
		"repository:namespace",
		"repository:namespace:wrong",
		"something:bla/bla:push",
		"push:alpine/master:pull",
	}
	var err error
	for _, v := range invalidFormats {
		s := &Scope{}
		err = s.UnmarshalText([]byte(v))
		if err == nil {
			t.Fatalf("Expected an error for %s", v)
		}
	}

	validFormats := []struct {
		in  string
		out Scope
	}{
		{
			"repository:golja/godoauth:push,pull",
			Scope{
				Type:    "repository",
				Name:    "golja/godoauth",
				Actions: PrivPull | PrivPush,
			},
		},
		{
			"repository:golja/godoauth:pull,push",
			Scope{
				Type:    "repository",
				Name:    "golja/godoauth",
				Actions: PrivPull | PrivPush,
			},
		},
		{
			"repository:golja/godoauth:pull",
			Scope{
				Type:    "repository",
				Name:    "golja/godoauth",
				Actions: PrivPull,
			},
		},
		{
			"repository:golja/godoauth:push",
			Scope{
				Type:    "repository",
				Name:    "golja/godoauth",
				Actions: PrivPush,
			},
		},
	}

	for _, v := range validFormats {
		s := &Scope{}
		err = s.UnmarshalText([]byte(v.in))
		if err != nil {
			t.Errorf("unexpected error for %s", v)
		}
		if *s != v.out {
			t.Errorf("UnmarshalText(%q) = %v, expected %v", v.in, *s, v.out)
		}
	}
}
