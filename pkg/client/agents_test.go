// pkg/client/agents_test.go
package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testConnectors = []Connector{
	{Name: "conn-1", UUIDURL: "uuid-1"},
	{Name: "conn-2", UUIDURL: "uuid-2"},
	{Name: "", UUIDURL: ""}, // filtered
}

func TestGetAgents(t *testing.T) {
	tests := map[string]struct {
		handler   http.HandlerFunc
		wantCount int
		wantErr   bool
	}{
		"success": {
			handler:   jsonHandler(http.StatusOK, ConnectorResponse{Connectors: testConnectors}),
			wantCount: 2,
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "error"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec, cleanup := newTestClient(t, tt.handler)
			defer cleanup()

			agents, err := GetAgents(ec)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, agents, tt.wantCount)
		})
	}
}

func TestGetAgentUUIDs(t *testing.T) {
	handler := jsonHandler(http.StatusOK, ConnectorResponse{Connectors: testConnectors})

	tests := map[string]struct {
		names     []string
		wantUUIDs []string
		wantErr   bool
	}{
		"all_found": {
			names:     []string{"conn-1", "conn-2"},
			wantUUIDs: []string{"uuid-1", "uuid-2"},
		},
		"one_not_found": {
			names:   []string{"conn-1", "conn-missing"},
			wantErr: true,
		},
		"empty_names": {
			names:     []string{},
			wantUUIDs: []string{},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec, cleanup := newTestClient(t, handler)
			defer cleanup()

			got, err := GetAgentUUIDs(ec, tt.names)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantUUIDs, got)
		})
	}
}

func TestDeleteConnector(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusNoContent, nil),
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "error"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec, cleanup := newTestClient(t, tt.handler)
			defer cleanup()

			err := DeleteConnector(ec, "test-uuid")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestCreateConnector(t *testing.T) {
	connResp := Connector{Name: "new-conn", UUIDURL: "new-uuid"}

	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, connResp),
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusBadRequest, "bad request"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec, cleanup := newTestClient(t, tt.handler)
			defer cleanup()

			req := &CreateConnectorRequest{
				Name:    "new-conn",
				Package: int(AGENT_PACKAGE_DOCKER),
				Status:  STATE_ENABLED,
			}
			got, err := req.CreateConnector(nil, ec)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "new-conn", got.Name)
		})
	}
}
