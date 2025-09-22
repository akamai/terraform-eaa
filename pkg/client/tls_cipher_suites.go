package client

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	ErrTLSCipherSuitesGet = errors.New("TLS cipher suites get failed")
)


type TLSCipherSuitesResponse struct {
	TLSCipherSuite map[string]TLSCipherSuite `json:"tls_cipher_suite"`
	TLSSuiteName   string                    `json:"tls_suite_name"`
}

func GetTLSCipherSuites(ec *EaaClient, appUUIDURL string) (*TLSCipherSuitesResponse, error) {
	apiURL := fmt.Sprintf("%s://%s/crux/v1/mgmt-pop/apps/%s", URL_SCHEME, ec.Host, appUUIDURL)
	
	tlsResponse := TLSCipherSuitesResponse{}

	getResp, err := ec.SendAPIRequest(apiURL, "GET", nil, &tlsResponse, true)
	if err != nil {
		return nil, err
	}
	
	
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc, _ := FormatErrorResponse(getResp)
		getTLSCipherSuitesErrMsg := fmt.Errorf("%w: %s", ErrTLSCipherSuitesGet, desc)
		return nil, getTLSCipherSuitesErrMsg
	}

	return &tlsResponse, nil
}
