package godoauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerPing(t *testing.T) {
	s := NewHandler(nil)

	request, err := http.NewRequest("GET", "/server-ping", nil)
	if err != nil {
		t.Fatalf("failed to create http.Request: %v", err)
	}

	response := httptest.NewRecorder()
	s.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Errorf("GET /server-ping got %v, expected %v", response.Code, http.StatusOK)
	}

	respData := struct {
		Message string
	}{}
	err = json.Unmarshal(response.Body.Bytes(), &respData)
	if err != nil {
		t.Fatalf("error unmarshalling JSON response: %v", err)
	}

	expectedMessage := "Save the Whales !"
	if respData.Message != expectedMessage {
		t.Errorf("response.Message = %q, expected %q", respData.Message, expectedMessage)
	}
}
