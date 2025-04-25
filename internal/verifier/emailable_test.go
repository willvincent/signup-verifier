package verifier

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEmailable_Verify_Deliverable(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"state":"deliverable"}`))
	}))
	defer mock.Close()

	em := &Emailable{APIKey: "key"}
	EmailableAPIBase = mock.URL

	ok, err := em.Verify("good@example.com")
	if err != nil || !ok {
		t.Errorf("expected success, got ok=%v, err=%v", ok, err)
	}
}

func TestEmailable_Verify_Unknown(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"state":"undeliverable"}`))
	}))
	defer mock.Close()

	em := &Emailable{APIKey: "key"}
	EmailableAPIBase = mock.URL

	ok, err := em.Verify("bad@example.com")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected undeliverable to return false")
	}
}

func TestEmailable_HTTPFailure(t *testing.T) {
	em := &Emailable{APIKey: "fail"}
	EmailableAPIBase = "http://127.0.0.1:9999" // no server

	_, err := em.Verify("fail@domain.com")
	if err == nil {
		t.Error("expected failure from bad endpoint")
	}
}
