package client

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendAPIRequest(t *testing.T) {
	tests := map[string]struct {
		in         interface{}
		wantErrIs  error
		handler    http.HandlerFunc
		checkQuery func(t *testing.T, query string)
		method     string
		wantStatus int
		global     bool
		wantErr    bool
	}{
		"GET_adds_contract_and_expand": {
			method:     http.MethodGet,
			global:     false,
			handler:    jsonHandler(http.StatusOK, map[string]string{"ok": "true"}),
			wantStatus: http.StatusOK,
			checkQuery: func(t *testing.T, query string) {
				assert.Contains(t, query, "contractId=test-contract")
				assert.Contains(t, query, "expand=true")
				assert.Contains(t, query, "limit=0")
			},
		},
		"GET_global_skips_query_params": {
			method:     http.MethodGet,
			global:     true,
			handler:    jsonHandler(http.StatusOK, map[string]string{"result": "ok"}),
			wantStatus: http.StatusOK,
			checkQuery: func(t *testing.T, query string) {
				assert.NotContains(t, query, "contractId")
			},
		},
		"POST_sends_body": {
			method: http.MethodPost,
			global: false,
			in:     map[string]string{"name": "test"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				var body map[string]string
				json.NewDecoder(r.Body).Decode(&body)
				assert.Equal(t, "test", body["name"])
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]string{"status": "created"})
			},
			wantStatus: http.StatusCreated,
		},
		"unmarshals_response_into_out": {
			method:     http.MethodGet,
			global:     false,
			handler:    jsonHandler(http.StatusOK, map[string]string{"key": "value"}),
			wantStatus: http.StatusOK,
		},
		"error_status_does_not_unmarshal_out": {
			method:     http.MethodGet,
			global:     false,
			handler:    jsonHandler(http.StatusBadRequest, map[string]string{"error": "bad"}),
			wantStatus: http.StatusBadRequest,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var capturedQuery string
			wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedQuery = r.URL.RawQuery
				tt.handler(w, r)
			})
			ec, cleanup := newTestClient(t, wrappedHandler)
			defer cleanup()

			var out map[string]string
			resp, err := ec.SendAPIRequest(
				"https://"+ec.Host+"/crux/v1/mgmt-pop/test",
				tt.method, tt.in, &out, tt.global,
			)
			if tt.wantErr {
				require.Error(t, err)
				if tt.wantErrIs != nil {
					assert.True(t, errors.Is(err, tt.wantErrIs))
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantStatus, resp.StatusCode)
			if tt.checkQuery != nil {
				tt.checkQuery(t, capturedQuery)
			}
		})
	}
}

func TestSendAPIRequest_ExpandFalseOverride(t *testing.T) {
	var capturedQuery string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	expand := false
	ec := &EaaClient{
		Signer: noopSigner{},
		Logger: hclog.NewNullLogger(),
		Client: ts.Client(),
		Host:   ts.Listener.Addr().String(),
	}

	_, err := ec.SendAPIRequest(
		"https://"+ec.Host+"/crux/v1/mgmt-pop/appbundle",
		http.MethodGet, nil, nil, false,
		GetRequestOptions{Expand: &expand},
	)
	require.NoError(t, err)
	assert.Contains(t, capturedQuery, "expand=false")
}

func TestSendAPIRequest_RejectsMultipleOptions(t *testing.T) {
	ec := &EaaClient{}
	_, err := ec.SendAPIRequest(
		"https://example.com/test", http.MethodGet,
		nil, nil, false,
		GetRequestOptions{}, GetRequestOptions{},
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument))
}

func TestSendAPIRequest_AccountSwitchKey(t *testing.T) {
	var capturedQuery string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	})
	ec, cleanup := newTestClient(t, handler)
	defer cleanup()
	ec.AccountSwitchKey = "test-switch-key"

	_, err := ec.SendAPIRequest(
		"https://"+ec.Host+"/crux/v1/test",
		http.MethodGet, nil, nil, false,
	)
	require.NoError(t, err)
	assert.Contains(t, capturedQuery, "accountSwitchKey=test-switch-key")
}

func TestFormatErrorDescription(t *testing.T) {
	tests := map[string]struct {
		resp *http.Response
		want string
	}{
		"nil_response": {
			resp: nil,
			want: "unknown error",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := FormatErrorDescription(tt.resp)
			assert.Equal(t, tt.want, got)
		})
	}
}
