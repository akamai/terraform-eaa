package client

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
			ec := newTestClient(t, wrappedHandler)

			var out map[string]string
			resp, err := ec.SendAPIRequest(
				"https://"+ec.Host+"/crux/v1/mgmt-pop/test",
				tt.method, tt.in, &out, tt.global,
			)
			if requireErr(t, err, tt.wantErr) {
				if tt.wantErrIs != nil {
					assert.True(t, errors.Is(err, tt.wantErrIs))
				}
				return
			}
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
	ec := newTestClient(t, handler)
	ec.AccountSwitchKey = "test-switch-key"

	_, err := ec.SendAPIRequest(
		"https://"+ec.Host+"/crux/v1/test",
		http.MethodGet, nil, nil, false,
	)
	require.NoError(t, err)
	assert.Contains(t, capturedQuery, "accountSwitchKey=test-switch-key")
}

func TestFormatErrorResponse(t *testing.T) {
	tests := map[string]struct {
		body       string
		wantDetail string
		wantErr    bool
	}{
		"valid_error_body": {
			body:       `{"type":"error","title":"Bad Request","detail":"invalid app_type"}`,
			wantDetail: "invalid app_type",
		},
		"malformed_json": {
			body:    `{not-json`,
			wantErr: true,
		},
		"empty_body": {
			body:    ``,
			wantErr: true,
		},
		"empty_json_object": {
			body:       `{}`,
			wantDetail: "",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			resp := &http.Response{
				Body: io.NopCloser(strings.NewReader(tc.body)),
			}
			detail, err := FormatErrorResponse(resp)
			if requireErr(t, err, tc.wantErr) {
				return
			}
			assert.Equal(t, tc.wantDetail, detail)
		})
	}
}

func TestFormatErrorDescription(t *testing.T) {
	tests := map[string]struct {
		resp     *http.Response
		expected string
	}{
		"nil_response": {
			resp:     nil,
			expected: "unknown error",
		},
		"with_error_detail": {
			resp: &http.Response{
				Body: io.NopCloser(strings.NewReader(`{"detail":"not found"}`)),
			},
			expected: "not found",
		},
		"malformed_body_falls_back_to_status": {
			resp: &http.Response{
				Status: "403 Forbidden",
				Body:   io.NopCloser(strings.NewReader(`{bad`)),
			},
			expected: "403 Forbidden",
		},
		"empty_detail_falls_back_to_status": {
			resp: &http.Response{
				Status: "500 Internal Server Error",
				Body:   io.NopCloser(strings.NewReader(`{}`)),
			},
			expected: "500 Internal Server Error",
		},
		"no_detail_no_status": {
			resp: &http.Response{
				Body: io.NopCloser(strings.NewReader(`{}`)),
			},
			expected: "unknown error",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := FormatErrorDescription(tc.resp)
			assert.Equal(t, tc.expected, result)
		})
	}
}
