package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendAPIRequest(t *testing.T) {
	tests := map[string]struct {
		in         interface{}
		wantErrIs  error
		handler    http.HandlerFunc
		checkQuery func(t *testing.T, query string)
		checkOut   func(t *testing.T, out map[string]string)
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
				require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
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
			checkOut: func(t *testing.T, out map[string]string) {
				assert.Equal(t, "value", out["key"])
			},
		},
		"error_status_does_not_unmarshal_out": {
			method:     http.MethodGet,
			global:     false,
			handler:    jsonHandler(http.StatusBadRequest, map[string]string{"error": "bad"}),
			wantStatus: http.StatusBadRequest,
			checkOut: func(t *testing.T, out map[string]string) {
				assert.Empty(t, out)
			},
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
				context.Background(),
				"https://"+ec.Host+"/crux/v1/mgmt-pop/test",
				tt.method, tt.in, &out, tt.global,
			)
			if requireErrIs(t, err, tt.wantErr, nil) {
				if tt.wantErrIs != nil {
					assert.True(t, errors.Is(err, tt.wantErrIs))
				}
				return
			}
			assert.Equal(t, tt.wantStatus, resp.StatusCode)
			if tt.checkQuery != nil {
				tt.checkQuery(t, capturedQuery)
			}
			if tt.checkOut != nil {
				tt.checkOut(t, out)
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
		Client: ts.Client(),
		Host:   ts.Listener.Addr().String(),
	}

	_, err := ec.SendAPIRequest(
		context.Background(),
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
		context.Background(),
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
		context.Background(),
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
			if requireErrIs(t, err, tc.wantErr, nil) {
				return
			}
			assert.Equal(t, tc.wantDetail, detail)
		})
	}
}

func TestSendMultipartRequest(t *testing.T) {
	tests := map[string]struct {
		handler     http.HandlerFunc
		fields      map[string]string
		fileField   string
		fileContent []byte
		wantStatus  int
		wantErr     bool
	}{
		"sends_fields_and_file": {
			fields:      map[string]string{"name": "my-cert", "cert_type": "6"},
			fileField:   "cert",
			fileContent: []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST", r.Method)
				assert.Contains(t, r.Header.Get("Content-Type"), "multipart/form-data")

				err := r.ParseMultipartForm(10 << 20)
				require.NoError(t, err)
				assert.Equal(t, "my-cert", r.FormValue("name"))
				assert.Equal(t, "6", r.FormValue("cert_type"))

				file, header, err := r.FormFile("cert")
				require.NoError(t, err)
				defer file.Close()
				assert.Equal(t, "cert.crt", header.Filename)
				content, _ := io.ReadAll(file)
				assert.Contains(t, string(content), "BEGIN CERTIFICATE")

				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			},
			wantStatus: http.StatusOK,
		},
		"adds_contract_id_to_query": {
			fields:      map[string]string{"name": "test"},
			fileField:   "cert",
			fileContent: []byte("cert-data"),
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Contains(t, r.URL.RawQuery, "contractId=test-contract")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
			},
			wantStatus: http.StatusOK,
		},
		"adds_account_switch_key": {
			fields:      map[string]string{"name": "test"},
			fileField:   "cert",
			fileContent: []byte("cert-data"),
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Contains(t, r.URL.RawQuery, "accountSwitchKey=test-switch")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
			},
			wantStatus: http.StatusOK,
		},
		"nil_file_content_skips_file_field": {
			fields:      map[string]string{"name": "test"},
			fileField:   "cert",
			fileContent: nil,
			handler: func(w http.ResponseWriter, r *http.Request) {
				err := r.ParseMultipartForm(10 << 20)
				require.NoError(t, err)
				assert.Equal(t, "test", r.FormValue("name"))
				_, _, err = r.FormFile("cert")
				assert.Error(t, err, "expected no file field when fileContent is nil")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
			},
			wantStatus: http.StatusOK,
		},
		"api_error_status": {
			fields:      map[string]string{"name": "test"},
			fileField:   "cert",
			fileContent: []byte("cert-data"),
			handler:     errorJSONHandler(http.StatusBadRequest, "bad request"),
			wantStatus:  http.StatusBadRequest,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, http.HandlerFunc(tt.handler))
			if name == "adds_account_switch_key" {
				ec.AccountSwitchKey = "test-switch"
			}

			resp, err := ec.SendMultipartRequest(
				context.Background(),
				"https://"+ec.Host+"/crux/v1/mgmt-pop/certificates",
				tt.fields, tt.fileField, tt.fileContent,
			)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, tt.wantStatus, resp.StatusCode)

			// Verify response body is re-readable
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.NotEmpty(t, body)
		})
	}
}

func TestSendMultipartRequest_InvalidURL(t *testing.T) {
	ec := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	_, err := ec.SendMultipartRequest(
		context.Background(),
		"://bad-url",
		map[string]string{}, "cert", nil,
	)
	require.Error(t, err)
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
