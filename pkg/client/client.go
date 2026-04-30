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
	Signer           edgegrid.Signer
	Logger           hclog.Logger
	Client           *http.Client
	ContractID       string
	AccountSwitchKey string
	Host             string
}

type ErrorResponse struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Instance  string `json:"instance"`
	Detail    string `json:"detail"`
	ProblemID string `json:"problemId"`
}

// SendAPIRequest signs and executes the request using the client edgegrid config.
func (ec *EaaClient) SendAPIRequest(apiURL, method string, in, out interface{}, global bool) (*http.Response, error) {
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

	}

	ec.Logger.Info(apiURL)
	r, err := http.NewRequest(method, apiURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	r.Header.Set("Content-Type", "application/json")

	r.URL.RawQuery = r.URL.Query().Encode()
	if in != nil {
		data, marshalErr := json.Marshal(in)
		if marshalErr != nil {
			return nil, fmt.Errorf("%w: %s", ErrMarshaling, marshalErr)
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

func FormatErrorDescription(errResp *http.Response) string {
	if errResp == nil {
		return "unknown error"
	}

	desc, err := FormatErrorResponse(errResp)
	if err == nil && desc != "" {
		return desc
	}

	if errResp.Status != "" {
		return errResp.Status
	}

	return "unknown error"
}
