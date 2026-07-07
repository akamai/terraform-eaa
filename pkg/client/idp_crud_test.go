package client

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateIDP(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		req     IDPCreateRequest
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, IDPFullResponse{
				Name:    "test-idp",
				UUIDURL: "idp-uuid-123",
			}),
			req: IDPCreateRequest{Name: "test-idp", IDPType: 2},
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "create failed"),
			req:     IDPCreateRequest{Name: "test-idp", IDPType: 2},
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			resp, err := CreateIDP(context.Background(), ec, &tt.req)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "test-idp", resp.Name)
			assert.Equal(t, "idp-uuid-123", resp.UUIDURL)
		})
	}
}

func TestGetIDP(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, IDPFullResponse{
				Name:    "test-idp",
				UUIDURL: "idp-uuid-123",
				IDPType: 2,
			}),
		},
		"not_found": {
			handler: errorJSONHandler(http.StatusNotFound, "not found"),
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			resp, err := GetIDP(context.Background(), ec, "idp-uuid-123")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "test-idp", resp.Name)
		})
	}
}

func TestUpdateIDP(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, IDPFullResponse{
				Name:    "updated-idp",
				UUIDURL: "idp-uuid-123",
			}),
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "update failed"),
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			resp, err := UpdateIDP(context.Background(), ec, "idp-uuid-123", &IDPFullResponse{Name: "updated-idp"})
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "updated-idp", resp.Name)
		})
	}
}

func TestDeleteIDP(t *testing.T) {
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
			handler: errorJSONHandler(http.StatusInternalServerError, "delete failed"),
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			err := DeleteIDP(context.Background(), ec, "idp-uuid-123")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestDeployIDP(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, map[string]string{"cmdid": "cmd-123"}),
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "deploy failed"),
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			err := DeployIDP(context.Background(), ec, "idp-uuid-123")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestGetPopByName(t *testing.T) {
	pr := newPathRouter(t)
	pr.Handle("GET", "/crux/v1/mgmt-pop/pops", jsonHandler(http.StatusOK, PopResponse{
		Pops: []Pop{
			{Name: "us-east-pop", UUIDURL: "pop-uuid-1", Region: "us-east-1"},
			{Name: "us-west-pop", UUIDURL: "pop-uuid-2", Region: "us-west-1"},
		},
	}))

	tests := map[string]struct {
		name    string
		wantErr bool
	}{
		"found":     {name: "us-east-pop"},
		"not_found": {name: "nonexistent", wantErr: true},
	}

	for testName, tt := range tests {
		t.Run(testName, func(t *testing.T) {
			ec := newTestClient(t, pr)
			pop, err := GetPopByName(context.Background(), ec, tt.name)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.name, pop.Name)
		})
	}
}
