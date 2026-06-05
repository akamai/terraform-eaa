package client

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testConnectors() []Connector {
	return []Connector{
		{Name: "conn-1", UUIDURL: "uuid-1"},
		{Name: "conn-2", UUIDURL: "uuid-2"},
		{Name: "", UUIDURL: ""}, // filtered
	}
}

func TestGetAgents(t *testing.T) {
	tests := map[string]struct {
		handler   http.HandlerFunc
		wantCount int
		wantErr   bool
	}{
		"success": {
			handler:   jsonHandler(http.StatusOK, ConnectorResponse{Connectors: testConnectors()}),
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

			agents, err := GetAgents(context.Background(), ec)
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
			assert.Len(t, agents, tt.wantCount)
		})
	}
}

func TestGetAgentUUIDs(t *testing.T) {
	handler := jsonHandler(http.StatusOK, ConnectorResponse{Connectors: testConnectors()})

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
			ec := newTestClient(t, handler)

			got, err := GetAgentUUIDs(context.Background(), ec, tt.names)
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
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
			ec := newTestClient(t, tt.handler)

			err := DeleteConnector(context.Background(), ec, "test-uuid")
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
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
			ec := newTestClient(t, tt.handler)

			req := &CreateConnectorRequest{
				Name:    "new-conn",
				Package: int(AGENT_PACKAGE_DOCKER),
				Status:  STATE_ENABLED,
			}
			got, err := req.CreateConnector(context.Background(), ec)
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
			assert.Equal(t, "new-conn", got.Name)
		})
	}
}
