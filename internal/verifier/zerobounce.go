package verifier

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type ZeroBounce struct {
	APIKey string
}

func init() {
	Register("zerobounce", func(apiKey string) Verifier {
		return NewZeroBounce(apiKey)
	})
}



func NewZeroBounce(apiKey string) *ZeroBounce {
	return &ZeroBounce{APIKey: apiKey}
}

func (z *ZeroBounce) Verify(email string) (bool, error) {
	reqUrl := fmt.Sprintf("https://api.zerobounce.net/v2/validate?api_key=%s&email=%s", z.APIKey, url.QueryEscape(email))
	resp, err := http.Get(reqUrl)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result struct {
		Status string `json:"status"` // "valid", "invalid", etc.
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}
	return result.Status == "valid", nil
}
