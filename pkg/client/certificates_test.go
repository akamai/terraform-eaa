package client

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"git.source.akamai.com/terraform-provider-eaa/pkg/testsupport"
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

			certs, err := GetCertificates(context.Background(), ec)
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
			assert.Len(t, certs, tt.wantCount)
		})
	}
}

// TestGetCertificatesPagination proves GetCertificates walks past the first
// page. Regression test for BWVONE-50686: a cert beyond page 1 was invisible
// to DoesUploadedCertExist, so app create with cert_type="uploaded" failed
// with "uploaded certificate for host 'X' not found".
func TestGetCertificatesPagination(t *testing.T) {
	page1 := make([]CertObject, 0, 25)
	for i := 0; i < 25; i++ {
		page1 = append(page1, CertObject{
			Name:     fmt.Sprintf("cert-page1-%d", i),
			UUIDURL:  fmt.Sprintf("uuid-p1-%d", i),
			CertType: CERT_TYPE_APP,
		})
	}
	nextURL := "next-page"
	page2 := []CertObject{
		{Name: "app-cert-from-vault-kv", UUIDURL: "uuid-p2-0", CertType: CERT_TYPE_APP},
		{Name: "cert-page2-1", UUIDURL: "uuid-p2-1", CertType: CERT_TYPE_APP},
	}

	var requestCount int
	handler := func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		offset := r.URL.Query().Get("offset")
		switch offset {
		case "", "0":
			testsupport.WriteJSONResponse(w, http.StatusOK, CertsResponse{
				Objects: page1,
				Meta:    Meta{Next: &nextURL, Limit: 25, TotalCount: 27},
			})
		case "25":
			testsupport.WriteJSONResponse(w, http.StatusOK, CertsResponse{
				Objects: page2,
				Meta:    Meta{Limit: 25, TotalCount: 27},
			})
		default:
			t.Fatalf("unexpected offset: %q", offset)
		}
	}

	ec := newTestClient(t, http.HandlerFunc(handler))
	certs, err := GetCertificates(context.Background(), ec)
	require.NoError(t, err)
	assert.Equal(t, 2, requestCount, "expected pagination to make two requests")
	assert.Len(t, certs, 27, "expected certs from both pages")

	cert, err := DoesUploadedCertExist(context.Background(), ec, "app-cert-from-vault-kv")
	require.NoError(t, err, "cert on page 2 must be findable after pagination")
	require.NotNil(t, cert)
	assert.Equal(t, "uuid-p2-0", cert.UUIDURL)
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

			cert, err := DoesSelfSignedCertExistForHost(context.Background(), ec, tt.host)
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

			cert, err := DoesUploadedCertExist(context.Background(), ec, tt.host)
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

			got, err := GetCertificate(context.Background(), ec, "cert-uuid-1")
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
			assert.Equal(t, "test.example.com", got.HostName)
		})
	}
}

func testExpandedCertResponse() CertificateExpandedResponse {
	return CertificateExpandedResponse{
		CertificateResponse: CertificateResponse{
			Name:     "test-cert",
			UUIDURL:  "test-uuid",
			Cert:     "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			CN:       "localhost",
			CertType: CERT_TYPE_APP,
			Status:   1,
			AppCount: 1,
			DirCount: 0,
			DaysLeft: 364,
		},
		Apps: []AssociatedObject{{Name: "app1", UUIDURL: "app-uuid-1", Status: 1}},
		IDPs: []AssociatedObject{},
	}
}

func TestGetCertificateExpanded(t *testing.T) {
	tests := map[string]struct {
		handler      http.HandlerFunc
		wantSentinel error
		wantErr      bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, testExpandedCertResponse()),
		},
		"not_found": {
			handler:      errorJSONHandler(http.StatusNotFound, "not found"),
			wantErr:      true,
			wantSentinel: ErrCertNotFound,
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "error"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			resp, err := GetCertificateExpanded(context.Background(), ec, "test-uuid")
			if tt.wantErr {
				require.Error(t, err)
				if tt.wantSentinel != nil {
					assert.ErrorIs(t, err, tt.wantSentinel)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "test-cert", resp.Name)
			assert.Len(t, resp.Apps, 1)
		})
	}
}

func TestDeleteCertificate(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "error"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			err := DeleteCertificate(context.Background(), ec, "test-uuid")
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCreateAppCertificate(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, CertificateResponse{
				UUIDURL:  "new-cert-uuid",
				Name:     "my-cert",
				CertType: CERT_TYPE_APP,
			}),
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusBadRequest, "invalid cert"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			req := &CreateAppCertRequest{
				CertType:   CERT_TYPE_APP,
				Name:       "my-cert",
				Cert:       "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
				PrivateKey: "-----BEGIN RSA " + "PRIVATE KEY-----\ntest\n-----END RSA " + "PRIVATE KEY-----",
				Password:   "",
			}
			resp, err := CreateAppCertificate(context.Background(), ec, req)
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
			assert.Equal(t, "new-cert-uuid", resp.UUIDURL)
		})
	}
}

func TestUpdateAppCertificate(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, CertificateResponse{UUIDURL: "cert-uuid", Name: "updated-cert"}),
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "update failed"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			req := &UpdateAppCertRequest{
				CertType:   CERT_TYPE_APP,
				Name:       "updated-cert",
				Cert:       "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
				PrivateKey: "-----BEGIN RSA " + "PRIVATE KEY-----\ntest\n-----END RSA " + "PRIVATE KEY-----",
				Password:   "",
			}
			resp, err := UpdateAppCertificate(context.Background(), ec, "cert-uuid", req)
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
			assert.Equal(t, "updated-cert", resp.Name)
		})
	}
}

func TestGetCertificateAssociated(t *testing.T) {
	tests := map[string]struct {
		handler        http.HandlerFunc
		wantAssociated bool
		wantErr        bool
	}{
		"associated_true": {
			handler: jsonHandler(http.StatusOK, CertThinResponse{
				Objects: []CertThinObject{
					{Name: "my-cert", UUIDURL: "cert-uuid", Associated: true},
				},
			}),
			wantAssociated: true,
		},
		"associated_false": {
			handler: jsonHandler(http.StatusOK, CertThinResponse{
				Objects: []CertThinObject{
					{Name: "my-cert", UUIDURL: "cert-uuid", Associated: false},
				},
			}),
			wantAssociated: false,
		},
		"not_found": {
			handler: jsonHandler(http.StatusOK, CertThinResponse{
				Objects: []CertThinObject{
					{Name: "other-cert", UUIDURL: "other-uuid", Associated: true},
				},
			}),
			wantAssociated: false,
		},
		"empty_objects": {
			handler: jsonHandler(http.StatusOK, CertThinResponse{
				Objects: []CertThinObject{},
			}),
			wantAssociated: false,
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "error"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			associated, err := GetCertificateAssociated(context.Background(), ec, "cert-uuid", "my-cert", CERT_TYPE_APP)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantAssociated, associated)
		})
	}
}

func TestDeployCertificate(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, map[string]string{"message": "Certificate deployment initiated."}),
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "deploy failed"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			err := DeployCertificate(context.Background(), ec, "cert-uuid")
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCreateCACertificate(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, CertificateResponse{
				UUIDURL:  "ca-cert-uuid",
				Name:     "my-ca",
				CertType: CERT_TYPE_CA,
			}),
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusBadRequest, "invalid ca cert"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			resp, err := CreateCACertificate(context.Background(), ec, "my-ca", "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----", "")
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
			assert.Equal(t, "ca-cert-uuid", resp.UUIDURL)
		})
	}
}

func TestUpdateCACertificate(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, map[string]string{"cert": "updated"}),
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "upload failed"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			err := UpdateCACertificate(context.Background(), ec, "ca-cert-uuid", "my-ca", "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----", "")
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
