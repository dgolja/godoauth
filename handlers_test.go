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
