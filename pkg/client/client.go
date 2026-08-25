package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
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
		return nil, logging.Wrapf(ErrInvalidArgument, []logging.Tag{logging.TagAPI, logging.TagValidate}, "expected at most one GetRequestOptions, got %d", len(opts))
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
	defer resp.Body.Close() //nolint:errcheck // best-effort close on HTTP response body

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

// SendMultipartRequest sends a multipart/form-data request to the API.
// It builds a multipart form with the provided fields and file content,
// signs the request, and returns the response for the caller to parse.
func (ec *EaaClient) SendMultipartRequest(ctx context.Context, apiURL string, fields map[string]string, fileFieldName string, fileContent []byte) (*http.Response, error) {
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
	parsedURL.RawQuery = queryParams.Encode()
	apiURL = parsedURL.String()

	logging.Debug(ctx, "sending multipart API request", []logging.Tag{logging.TagAPI}, map[string]any{"url": apiURL})

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	for key, val := range fields {
		if fieldErr := writer.WriteField(key, val); fieldErr != nil {
			return nil, logging.Wrapf(fieldErr, []logging.Tag{logging.TagAPI, logging.TagMarshal}, "failed to write multipart field %s", key)
		}
	}

	if fileContent != nil {
		part, partErr := writer.CreateFormFile(fileFieldName, "cert.crt")
		if partErr != nil {
			return nil, logging.Wrapf(partErr, []logging.Tag{logging.TagAPI, logging.TagMarshal}, "failed to create multipart file field")
		}
		if _, writeErr := part.Write(fileContent); writeErr != nil {
			return nil, logging.Wrapf(writeErr, []logging.Tag{logging.TagAPI, logging.TagMarshal}, "failed to write multipart file content")
		}
	}

	if closeErr := writer.Close(); closeErr != nil {
		return nil, logging.Wrapf(closeErr, []logging.Tag{logging.TagAPI, logging.TagMarshal}, "failed to close multipart writer")
	}

	r, err := http.NewRequest("POST", apiURL, &body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	r.Header.Set("Content-Type", writer.FormDataContentType())
	r.ContentLength = int64(body.Len())

	ec.Signer.SignRequest(r)

	resp, err := ec.Client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close on HTTP response body

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	logging.Debug(ctx, "received multipart API response", []logging.Tag{logging.TagAPI}, map[string]any{"status_code": resp.StatusCode})
	logging.Trace(ctx, "response body", []logging.Tag{logging.TagAPI}, map[string]any{"body": string(responseBody)})

	resp.Body = io.NopCloser(bytes.NewBuffer(responseBody))
	return resp, nil
}

// ValidatePEMContent checks that the content is a PEM-encoded certificate.
// Only PEM certificates (-----BEGIN CERTIFICATE-----) are supported.
func ValidatePEMContent(content []byte) error {
	trimmed := bytes.TrimSpace(content)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN CERTIFICATE-----")) {
		if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
			return fmt.Errorf("unsupported PEM type; only -----BEGIN CERTIFICATE----- is accepted")
		}
		return fmt.Errorf("certificate content must be PEM-encoded (-----BEGIN CERTIFICATE-----); binary formats such as DER, PKCS12, and PFX are not supported")
	}
	return nil
}

func FormatErrorResponse(errResp *http.Response) (string, error) {
	var errResponse ErrorResponse
	data, err := io.ReadAll(errResp.Body)
	if err != nil {
		return "", logging.Wrapf(err, []logging.Tag{logging.TagAPI, logging.TagMarshal}, "failed to read error response body")
	}
	// Reset the body so it can be read again if needed
	errResp.Body = io.NopCloser(bytes.NewBuffer(data))

	if unmarshalErr := json.Unmarshal(data, &errResponse); unmarshalErr != nil {
		return "", logging.Wrapf(unmarshalErr, []logging.Tag{logging.TagAPI, logging.TagMarshal}, "failed to unmarshal error response")
	}
	return errResponse.Detail, nil
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
