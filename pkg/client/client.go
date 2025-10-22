package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v6/pkg/edgegrid"
	"github.com/hashicorp/go-hclog"
)

type EaaClient struct {
	ContractID       string
	AccountSwitchKey string
	Client           *http.Client
	Signer           edgegrid.Signer
	Host             string
	Logger           hclog.Logger
}

type ErrorResponse struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Instance  string `json:"instance"`
	Detail    string `json:"detail"`
	ProblemID string `json:"problemId"`
}

// Exec will sign and execute the request using the client edgegrid.Config
func (ec *EaaClient) SendAPIRequest(apiURL string, method string, in interface{}, out interface{}, global bool) (*http.Response, error) {
	if !global {
		parsedURL, err := url.Parse(apiURL)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrMarshaling, err)
		}
		queryParams := parsedURL.Query()
		if ec.ContractID != "" {
			queryParams.Set("contractId", ec.ContractID)
		}
		if ec.AccountSwitchKey != "" {
			queryParams.Set("accountSwitchKey", ec.AccountSwitchKey)
		}
		if method == http.MethodGet {
			queryParams.Set("expand", "true")
			queryParams.Set("limit", "0")
		}
		parsedURL.RawQuery = queryParams.Encode()

		apiURL = parsedURL.String()

		// apiURL = fmt.Sprintf("%s?%s", apiURL, queryParams.Encode())
	}

	ec.Logger.Info(apiURL)
	r, _ := http.NewRequest(method, apiURL, nil)
	r.Header.Set("Content-Type", "application/json")

	r.URL.RawQuery = r.URL.Query().Encode()
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrMarshaling, err)
		}

		r.Body = io.NopCloser(bytes.NewBuffer(data))
		r.ContentLength = int64(len(data))
	}
	ec.Signer.SignRequest(r)

	resp, err := ec.Client.Do(r)
	if err != nil {
		return nil, err
	}

	// Read the response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Create a new reader for the unmarshaling
	resp.Body = io.NopCloser(bytes.NewBuffer(responseBody))

	// Unmarshal the response if needed
	if out != nil &&
		resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices &&
		resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusResetContent {
		if err := json.Unmarshal(responseBody, out); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrUnmarshaling, err)
		}
	}

	return resp, nil
}

func FormatErrorResponse(errResp *http.Response) (string, error) {
	var errResponse ErrorResponse
	data, err := io.ReadAll(errResp.Body)

	if err == nil {
		err := json.Unmarshal(data, &errResponse)
		if err != nil {
			return "", ErrUnmarshaling
		}
		return errResponse.Detail, nil
	}
	return "", ErrUnmarshaling
}
