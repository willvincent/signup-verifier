package verifier

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestZeroBounce_Verify_Valid(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No path check for now
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"valid"}`))
	}))
	
	defer mock.Close()

	zb := &ZeroBounce{APIKey: "fake"}
	ZeroBounceAPIBase = mock.URL

	ok, err := zb.Verify("user@example.com")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !ok {
		t.Errorf("expected email to be valid")
	}
}

func TestZeroBounce_Verify_Invalid(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"invalid"}`))
	}))
	defer mock.Close()

	zb := &ZeroBounce{APIKey: "fake"}
	ZeroBounceAPIBase = mock.URL

	ok, err := zb.Verify("fake@invalid.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Errorf("expected invalid email")
	}
}

func TestZeroBounce_HTTPFailure(t *testing.T) {
	zb := &ZeroBounce{APIKey: "fake"}
	ZeroBounceAPIBase = "http://127.0.0.1:9999" // force fail

	_, err := zb.Verify("fail@nowhere.com")
	if err == nil {
		t.Errorf("expected error on unreachable ZeroBounce endpoint")
	}
}
