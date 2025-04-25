package verifier

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

var EmailableAPIBase = "https://api.emailable.com/v1"

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
	reqUrl := fmt.Sprintf("%s/verify?email=%s&api_key=%s", EmailableAPIBase, url.QueryEscape(email), e.APIKey)
	resp, err := http.Get(reqUrl)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result struct {
		Deliverability string `json:"state"` // "deliverable", "undeliverable"
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}
	return result.Deliverability == "deliverable", nil
}
