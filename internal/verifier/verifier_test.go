package verifier_test

import (
	"errors"
	"testing"

	"github.com/willvincent/signup-verifier/internal/verifier"
)

func init() {
	verifier.Register("dummy", func(apiKey string) verifier.Verifier {
		return &dummyVerifier{}
	})
}

type dummyVerifier struct{}

func (d *dummyVerifier) Verify(email string) (bool, error) {
	if email == "fail@example.com" {
		return false, errors.New("boom")
	}
	return true, nil
}

func TestRegisterAndResolve(t *testing.T) {
	v, err := verifier.NewFromProvider("dummy", "apikey")
	if err != nil {
		t.Fatalf("Expected resolver to succeed, got %v", err)
	}

	valid, err := v.Verify("user@example.com")
	if !valid || err != nil {
		t.Errorf("Expected verify to succeed")
	}

	_, err = verifier.NewFromProvider("not-registered", "")
	if err == nil {
		t.Errorf("Expected error on unknown provider")
	}
}

func TestNewFromProvider_Unknown(t *testing.T) {
	_, err := verifier.NewFromProvider("notreal", "")
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

type testVerifier struct {
	result bool
	err    error
}

func (tv *testVerifier) Verify(email string) (bool, error) {
	return tv.result, tv.err
}

func TestNewFromProvider_Valid(t *testing.T) {
	verifier.Register("test", func(apiKey string) verifier.Verifier {
		return &testVerifier{result: true}
	})

	v, err := verifier.NewFromProvider("test", "fake-key")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	ok, err := v.Verify("test@example.com")
	if !ok || err != nil {
		t.Errorf("expected verify true with no error, got %v %v", ok, err)
	}
}

func TestVerifier_VerifyFails(t *testing.T) {
	verifier.Register("failer", func(apiKey string) verifier.Verifier {
		return &testVerifier{
			result: false,
			err:    errors.New("simulated failure"),
		}
	})

	v, err := verifier.NewFromProvider("failer", "fake")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ok, err := v.Verify("fail@example.com")
	if ok || err == nil {
		t.Errorf("expected failure, got ok=%v err=%v", ok, err)
	}
}

func TestRegister_PanicsOnDuplicate(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic when re-registering provider, but got none")
		}
	}()

	verifier.Register("dupe", func(apiKey string) verifier.Verifier {
		return &testVerifier{result: true}
	})
	// should panic here:
	verifier.Register("dupe", func(apiKey string) verifier.Verifier {
		return &testVerifier{result: false}
	})
}
