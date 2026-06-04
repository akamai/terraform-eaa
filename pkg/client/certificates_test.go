package client

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCerts() []CertObject {
	return []CertObject{
		{Name: "app.example.com", UUIDURL: "cert-uuid-1", CertType: CERT_TYPE_APP_SSC},
		{Name: "app2.example.com", UUIDURL: "cert-uuid-2", CertType: CERT_TYPE_APP},
		{Name: "", UUIDURL: ""}, // filtered
	}
}

func TestGetCertificates(t *testing.T) {
	tests := map[string]struct {
		handler   http.HandlerFunc
		wantCount int
		wantErr   bool
	}{
		"success": {
			handler:   jsonHandler(http.StatusOK, CertsResponse{Objects: testCerts()}),
			wantCount: 2,
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "error"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)

			certs, err := GetCertificates(ec)
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
			assert.Len(t, certs, tt.wantCount)
		})
	}
}

func TestDoesSelfSignedCertExistForHost(t *testing.T) {
	handler := jsonHandler(http.StatusOK, CertsResponse{Objects: testCerts()})

	tests := map[string]struct {
		host    string
		wantNil bool
	}{
		"found":      {host: "app.example.com", wantNil: false},
		"not_found":  {host: "missing.example.com", wantNil: true},
		"wrong_type": {host: "app2.example.com", wantNil: true}, // cert_type is APP, not SSC
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, handler)

			cert, err := DoesSelfSignedCertExistForHost(ec, tt.host)
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, cert)
			} else {
				assert.NotNil(t, cert)
			}
		})
	}
}

func TestDoesUploadedCertExist(t *testing.T) {
	handler := jsonHandler(http.StatusOK, CertsResponse{Objects: testCerts()})

	tests := map[string]struct {
		host    string
		wantErr bool
	}{
		"found_uploaded":           {host: "app2.example.com", wantErr: false},
		"not_found":                {host: "missing.example.com", wantErr: true},
		"self_signed_not_uploaded": {host: "app.example.com", wantErr: true}, // SSC type, not uploaded
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, handler)

			cert, err := DoesUploadedCertExist(ec, tt.host)
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
			assert.NotNil(t, cert)
		})
	}
}

func TestCreateSelfSignedCertificate(t *testing.T) {
	certResp := CertificateResponse{HostName: "test.example.com", UUIDURL: "cert-uuid"}

	tests := map[string]struct {
		handler  http.HandlerFunc
		hostname string
		wantErr  bool
	}{
		"success": {
			hostname: "test.example.com",
			handler:  jsonHandler(http.StatusOK, certResp),
		},
		"empty_hostname": {
			hostname: "",
			handler:  jsonHandler(http.StatusOK, nil),
			wantErr:  true,
		},
		"api_error": {
			hostname: "test.example.com",
			handler:  errorJSONHandler(http.StatusBadRequest, "error"),
			wantErr:  true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)

			req := &CreateSelfSignedCertRequest{HostName: tt.hostname}
			got, err := req.CreateSelfSignedCertificate(context.Background(), ec)
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
			assert.Equal(t, "test.example.com", got.HostName)
		})
	}
}

func TestGetCertificate(t *testing.T) {
	certResp := CertificateResponse{HostName: "test.example.com", UUIDURL: "cert-uuid-1"}

	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, certResp),
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusNotFound, "not found"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)

			got, err := GetCertificate(ec, "cert-uuid-1")
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
			assert.Equal(t, "test.example.com", got.HostName)
		})
	}
}
