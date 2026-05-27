package client

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-hclog"
)

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
		Logger: hclog.NewNullLogger(),
		Client: ts.Client(),
	}

	_, err := ec.SendAPIRequest(ts.URL+"/crux/v1/mgmt-pop/appbundle", http.MethodGet, nil, nil, false, GetRequestOptions{Expand: &expand})
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

	_, err := ec.SendAPIRequest(
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
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("SendAPIRequest() error = %v, want wrapped ErrInvalidArgument", err)
	}
}
