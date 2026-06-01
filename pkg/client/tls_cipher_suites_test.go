package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetTLSCipherSuites(t *testing.T) {
	testResp := TLSCipherSuitesResponse{
		TLSCipherSuite: map[string]TLSCipherSuite{
			"suite1": {},
			"suite2": {},
		},
		TLSSuiteName: "default",
	}

	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, testResp),
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "error"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)

			resp, err := GetTLSCipherSuites(ec, "test-app-uuid")
			if requireErr(t, err, tt.wantErr) {
				return
			}
			assert.Equal(t, "default", resp.TLSSuiteName)
			assert.Len(t, resp.TLSCipherSuite, 2)
		})
	}
}
