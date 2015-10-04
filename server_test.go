package godoauth

import (
	"encoding/json"
	"net/http"
	"testing"
)

var pingResponse = "Save the Whales !"

func newTestServer() *Server {
	config := &Config{
		HTTP: ServerConf{
			Addr:    "127.0.0.1:1234",
			Timeout: "5s",
			TLS: ServerTLS{
				Certificate: "certs/server.pem",
			},
		},
	}
	s, _ := NewServer(config)
	return s
}

// TestServerHandlers validate that mutex works as expected
// matching configStruct
func TestServerPing(t *testing.T) {
	s := newTestServer()
	s.Start()
	defer s.Close()

	resp, err := http.Get("http://127.0.0.1:1234/server-ping")
	if err != nil {
		t.Errorf("Error while retrieving server-ping: %s", err)
	} else if resp.StatusCode != 200 {
		t.Errorf("Server responded with incorrect response code, exp 200, got %d", resp.StatusCode)
	}

	respData := struct {
		Message string `json:"message"`
	}{}

	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&respData)
	if err != nil {
		t.Errorf("error parsing JSON response: %v", err)
	}
	if respData.Message != pingResponse {
		t.Errorf("Wrong response, exp '%s', got '%s'", respData.Message, pingResponse)
	}
}

// TestServerHandlers validate that mutex works as expected
// matching configStruct
func TestInvalidUrl(t *testing.T) {
	s := newTestServer()
	s.Start()
	defer s.Close()
	resp, _ := http.Get("http://127.0.0.1:1234/")
	if resp.StatusCode != 404 {
		t.Errorf("Expected error but received responce code: %s", resp.Status)
	}
}
