package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
)

type noopSigner struct{}

func (noopSigner) SignRequest(_ *http.Request) {}
func (noopSigner) CheckRequestLimit(_ int)     {}

func TestSendAPIRequestExpandFalseOverride(t *testing.T) {
	var capturedQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	expand := false
	ec := &EaaClient{
		Signer: noopSigner{},
		Client: ts.Client(),
	}

	ctx := context.Background()
	_, err := ec.SendAPIRequest(ctx, ts.URL+"/crux/v1/mgmt-pop/appbundle", http.MethodGet, nil, nil, false, GetRequestOptions{Expand: &expand})
	if err != nil {
		t.Fatalf("SendAPIRequest() returned unexpected error: %v", err)
	}

	parsed, _ := http.NewRequest(http.MethodGet, "?"+capturedQuery, http.NoBody)
	if got := parsed.URL.Query().Get("expand"); got != "false" {
		t.Fatalf("expand query param = %q, want %q", got, "false")
	}
}

func TestSendAPIRequestRejectsMultipleGetRequestOptions(t *testing.T) {
	ec := &EaaClient{}
	apiURL := "https://example.com/crux/v1/mgmt-pop/apps"

	ctx := context.Background()
	_, err := ec.SendAPIRequest(
		ctx,
		apiURL,
		http.MethodGet,
		nil,
		nil,
		false,
		GetRequestOptions{},
		GetRequestOptions{},
	)
	if err == nil {
		t.Fatal("SendAPIRequest() returned nil error, want non-nil")
	}
	if !logging.HasTag(err, logging.TagValidate) {
		t.Fatalf("SendAPIRequest() error = %v, want error with TagValidate", err)
	}
}
