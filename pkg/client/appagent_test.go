package client

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAppAgents(t *testing.T) {
	tests := map[string]struct {
		handler    http.HandlerFunc
		wantErrMsg string
		wantNames  []string
		wantErr    bool
	}{
		"success_with_agents": {
			handler: jsonHandler(http.StatusOK, AppAgentResponse{
				Agents: []struct {
					Agent struct {
						Name    string `json:"name,omitempty"`
						UUIDURL string `json:"uuid_url,omitempty"`
					} `json:"agent,omitempty"`
					ResourceURI struct {
						Href string `json:"href,omitempty"`
					} `json:"resource_uri,omitempty"`
				}{
					{
						Agent: struct {
							Name    string `json:"name,omitempty"`
							UUIDURL string `json:"uuid_url,omitempty"`
						}{Name: "agent-b", UUIDURL: "uuid-b"},
					},
					{
						Agent: struct {
							Name    string `json:"name,omitempty"`
							UUIDURL string `json:"uuid_url,omitempty"`
						}{Name: "agent-a", UUIDURL: "uuid-a"},
					},
				},
			}),
			wantNames: []string{"agent-a", "agent-b"}, // sorted
		},
		"empty_agents": {
			handler: jsonHandler(http.StatusOK, AppAgentResponse{
				Agents: nil,
			}),
			wantNames: []string{},
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "server error"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec, cleanup := newTestClient(t, tt.handler)
			defer cleanup()

			app := &Application{UUIDURL: "app-uuid-1"}
			got, err := app.GetAppAgents(ec)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantNames, got)
		})
	}
}

func TestAssignAgents(t *testing.T) {
	tests := map[string]struct {
		setupRouter func(pr *pathRouter)
		agentNames  []string
		wantErr     bool
	}{
		"success": {
			agentNames: []string{"conn-1"},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/agents", jsonHandler(http.StatusOK, ConnectorResponse{
					Connectors: []Connector{
						{Name: "conn-1", UUIDURL: "uuid-1"},
					},
				}))
				pr.Handle("POST", "/crux/v1/mgmt-pop/apps/app-123/agents", jsonHandler(http.StatusOK, nil))
			},
		},
		"empty_agent_names": {
			agentNames: []string{},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/agents", jsonHandler(http.StatusOK, ConnectorResponse{
					Connectors: []Connector{},
				}))
			},
			wantErr: false, // returns nil when no agents to assign
		},
		"agent_not_found": {
			agentNames: []string{"missing-agent"},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/agents", jsonHandler(http.StatusOK, ConnectorResponse{
					Connectors: []Connector{
						{Name: "conn-1", UUIDURL: "uuid-1"},
					},
				}))
			},
			wantErr: true,
		},
		"assign_api_error": {
			agentNames: []string{"conn-1"},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/agents", jsonHandler(http.StatusOK, ConnectorResponse{
					Connectors: []Connector{
						{Name: "conn-1", UUIDURL: "uuid-1"},
					},
				}))
				pr.Handle("POST", "/crux/v1/mgmt-pop/apps/app-123/agents", errorJSONHandler(http.StatusInternalServerError, "assign failed"))
			},
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			pr := newPathRouter()
			tt.setupRouter(pr)
			ec, cleanup := newTestClient(t, pr)
			defer cleanup()

			aar := &AssignAgents{
				AppID:      "app-123",
				AgentNames: tt.agentNames,
			}
			err := aar.AssignAgents(context.Background(), ec)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestUnAssignAgents(t *testing.T) {
	tests := map[string]struct {
		setupRouter func(pr *pathRouter)
		agentNames  []string
		wantErr     bool
	}{
		"success": {
			agentNames: []string{"conn-1"},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/agents", jsonHandler(http.StatusOK, ConnectorResponse{
					Connectors: []Connector{
						{Name: "conn-1", UUIDURL: "uuid-1"},
					},
				}))
				// UnAssignAgents uses ?method=delete in URL but the path router matches on path only
				pr.Handle("POST", "/crux/v1/mgmt-pop/apps/app-123/agents", jsonHandler(http.StatusOK, nil))
			},
		},
		"empty_agent_names": {
			agentNames: []string{},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/agents", jsonHandler(http.StatusOK, ConnectorResponse{
					Connectors: []Connector{},
				}))
			},
			wantErr: false,
		},
		"agent_lookup_fails": {
			agentNames: []string{"missing"},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/agents", jsonHandler(http.StatusOK, ConnectorResponse{
					Connectors: []Connector{
						{Name: "conn-1", UUIDURL: "uuid-1"},
					},
				}))
			},
			wantErr: true,
		},
		"unassign_api_error": {
			agentNames: []string{"conn-1"},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/agents", jsonHandler(http.StatusOK, ConnectorResponse{
					Connectors: []Connector{
						{Name: "conn-1", UUIDURL: "uuid-1"},
					},
				}))
				pr.Handle("POST", "/crux/v1/mgmt-pop/apps/app-123/agents", errorJSONHandler(http.StatusInternalServerError, "unassign failed"))
			},
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			pr := newPathRouter()
			tt.setupRouter(pr)
			ec, cleanup := newTestClient(t, pr)
			defer cleanup()

			aar := &AssignAgents{
				AppID:      "app-123",
				AgentNames: tt.agentNames,
			}
			err := aar.UnAssignAgents(context.Background(), ec)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
