package client

import (
	"context"
	"fmt"
	"net/http"

	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
)

type TLSCipherSuitesResponse struct {
	TLSCipherSuite map[string]TLSCipherSuite `json:"tls_cipher_suite"`
	TLSSuiteName   string                    `json:"tls_suite_name"`
}

func GetTLSCipherSuites(ctx context.Context, ec *EaaClient, appUUIDURL string) (*TLSCipherSuitesResponse, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagCipher, logging.TagRead}
	apiURL := fmt.Sprintf("%s://%s/crux/v1/mgmt-pop/apps/%s", URL_SCHEME, ec.Host, appUUIDURL)

	logging.Debug(ctx, "getting TLS cipher suites", tags, map[string]any{"url": apiURL, "app_uuid": appUUIDURL})

	tlsResponse := TLSCipherSuitesResponse{}

	getResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &tlsResponse, true)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "TLS cipher suites request failed")
	}

	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(getResp)
		return nil, logging.Errorf(tags, "TLS cipher suites get failed: %s", desc)
	}

	return &tlsResponse, nil
}
