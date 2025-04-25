package verifier

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type Emailable struct {
	APIKey string
}

func init() {
	Register("emailable", func(apiKey string) Verifier {
		return NewEmailable(apiKey)
	})
}



func NewEmailable(apiKey string) *Emailable {
	return &Emailable{APIKey: apiKey}
}

func (e *Emailable) Verify(email string) (bool, error) {
	reqUrl := fmt.Sprintf("https://api.emailable.com/v1/verify?email=%s&api_key=%s", url.QueryEscape(email), e.APIKey)
	resp, err := http.Get(reqUrl)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result struct {
		Deliverability string `json:"deliverability"` // "deliverable", "undeliverable"
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}
	return result.Deliverability == "deliverable", nil
}
