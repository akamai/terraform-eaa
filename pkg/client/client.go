package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v6/pkg/edgegrid"

	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
)

type EaaClient struct {
	Signer           edgegrid.Signer
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

// GetRequestOptions allows callers to customize GET query parameters in SendAPIRequest.
// When fields are nil, SendAPIRequest applies defaults: Expand=true, Limit=0.
type GetRequestOptions struct {
	Expand *bool
	Limit  *int
}

// SendAPIRequest signs and executes the request using the client edgegrid
// config. Optional opts customize GET query handling (expand/limit); defaults
// are Expand=true and Limit=0 when opts are not provided.
func (ec *EaaClient) SendAPIRequest(ctx context.Context, apiURL, method string, in, out interface{}, global bool, opts ...GetRequestOptions) (*http.Response, error) {
	if len(opts) > 1 {
		return nil, logging.Errorf([]logging.Tag{logging.TagAPI, logging.TagValidate}, "expected at most one GetRequestOptions, got %d", len(opts))
	}

	defaultExpand := true
	defaultLimit := 0
	options := GetRequestOptions{Expand: &defaultExpand, Limit: &defaultLimit}
	if len(opts) > 0 {
		if opts[0].Expand != nil {
			options.Expand = opts[0].Expand
		}
		if opts[0].Limit != nil {
			options.Limit = opts[0].Limit
		}
	}

	if !global {
		parsedURL, err := url.Parse(apiURL)
		if err != nil {
			return nil, logging.Wrapf(err, []logging.Tag{logging.TagAPI, logging.TagMarshal}, "failed to parse API URL")
		}
		queryParams := parsedURL.Query()
		if ec.ContractID != "" {
			queryParams.Set("contractId", ec.ContractID)
		}
		if ec.AccountSwitchKey != "" {
			queryParams.Set("accountSwitchKey", ec.AccountSwitchKey)
		}
		if method == http.MethodGet {
			queryParams.Set("expand", strconv.FormatBool(*options.Expand))
			queryParams.Set("limit", strconv.Itoa(*options.Limit))
		}
		parsedURL.RawQuery = queryParams.Encode()

		apiURL = parsedURL.String()

	}

	logging.Debug(ctx, "sending API request", []logging.Tag{logging.TagAPI}, map[string]any{"url": apiURL, "method": method})
	r, err := http.NewRequest(method, apiURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	r.Header.Set("Content-Type", "application/json")

	r.URL.RawQuery = r.URL.Query().Encode()
	if in != nil {
		data, marshalErr := json.Marshal(in)
		if marshalErr != nil {
			return nil, logging.Wrapf(marshalErr, []logging.Tag{logging.TagAPI, logging.TagMarshal}, "failed to marshal request")
		}

		logging.Trace(ctx, "request body", []logging.Tag{logging.TagAPI}, map[string]any{"body": string(data)})
		r.Body = io.NopCloser(bytes.NewBuffer(data))
		r.ContentLength = int64(len(data))
	}
	ec.Signer.SignRequest(r)

	resp, err := ec.Client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	logging.Debug(ctx, "received API response", []logging.Tag{logging.TagAPI}, map[string]any{"status_code": resp.StatusCode})
	logging.Trace(ctx, "response body", []logging.Tag{logging.TagAPI}, map[string]any{"body": string(responseBody)})

	// Create a new reader for the unmarshaling
	resp.Body = io.NopCloser(bytes.NewBuffer(responseBody))

	// Unmarshal the response if needed
	if out != nil &&
		resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices &&
		resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusResetContent {
		if err := json.Unmarshal(responseBody, out); err != nil {
			return nil, logging.Wrapf(err, []logging.Tag{logging.TagAPI, logging.TagMarshal}, "failed to unmarshal response")
		}
	}

	return resp, nil
}

func FormatErrorResponse(errResp *http.Response) (string, error) {
	var errResponse ErrorResponse
	data, err := io.ReadAll(errResp.Body)

	if err == nil {
		if unmarshalErr := json.Unmarshal(data, &errResponse); unmarshalErr != nil {
			return "", logging.Wrapf(unmarshalErr, []logging.Tag{logging.TagAPI, logging.TagMarshal}, "failed to unmarshal error response")
		}
		return errResponse.Detail, nil
	}
	return "", logging.Wrapf(err, []logging.Tag{logging.TagAPI, logging.TagMarshal}, "failed to read error response body")
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
