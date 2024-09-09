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
	if out != nil &&
		resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices &&
		resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusResetContent {
		data, err := io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(bytes.NewBuffer(data))
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, out); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrUnmarshaling, err)
		}
	}

	return resp, nil
}

func (ec *EaaClient) SendDeleteApplicationEndpoint(id string) error {
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, APPS_URL, id), nil)
	if err != nil {
		return err
	}
	req.URL.RawQuery = req.URL.Query().Encode()
	ec.Signer.SignRequest(req)

	resp, err := ec.Client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	return nil
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
