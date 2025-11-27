package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
)

// createMockClient creates an EaaClient with a mock HTTP server
func createMockClient(handler http.HandlerFunc) (*EaaClient, *httptest.Server) {
	server := httptest.NewTLSServer(handler)
	logger := hclog.NewNullLogger()
	
	// Extract host from server URL (remove https:// prefix)
	// httptest.NewTLSServer returns https://
	host := server.URL[8:] // Remove "https://" prefix
	
	// Create HTTP client that skips TLS verification for test server
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	
	client := &EaaClient{
		ContractID: "test-contract",
		Host:       host,
		Client:     httpClient,
		Signer:     &MockSigner{}, // Use MockSigner from test_helpers.go
		Logger:     logger,
	}
	
	return client, server
}

func TestGetAgents(t *testing.T) {
	tests := []struct {
		name      string
		handler   http.HandlerFunc
		wantErr   bool
		wantCount int
		wantNames []string
	}{
		{
			name: "successful get agents",
			handler: func(w http.ResponseWriter, r *http.Request) {
				// Handle GET requests to agents endpoint
				response := ConnectorResponse{
					Connectors: []Connector{
						{Name: "agent1", UUIDURL: "uuid1"},
						{Name: "agent2", UUIDURL: "uuid2"},
						{Name: "agent3", UUIDURL: "uuid3"},
					},
				}
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
			},
			wantErr:   false,
			wantCount: 3,
			wantNames: []string{"agent1", "agent2", "agent3"},
		},
		{
			name: "empty agents list",
			handler: func(w http.ResponseWriter, r *http.Request) {
				response := ConnectorResponse{
					Connectors: []Connector{},
				}
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
			},
			wantErr:   false,
			wantCount: 0,
			wantNames: []string{},
		},
		{
			name: "filters agents with missing name or uuid",
			handler: func(w http.ResponseWriter, r *http.Request) {
				response := ConnectorResponse{
					Connectors: []Connector{
						{Name: "agent1", UUIDURL: "uuid1"},
						{Name: "", UUIDURL: "uuid2"},      // Missing name - should be filtered
						{Name: "agent3", UUIDURL: ""},      // Missing UUID - should be filtered
						{Name: "agent4", UUIDURL: "uuid4"},
					},
				}
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
			},
			wantErr:   false,
			wantCount: 2,
			wantNames: []string{"agent1", "agent4"},
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				errorResp := ErrorResponse{
					Title:  "Internal Server Error",
					Detail: "Something went wrong",
				}
				json.NewEncoder(w).Encode(errorResp)
			},
			wantErr:   true,
			wantCount: 0,
			wantNames: nil,
		},
		{
			name: "not found error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				errorResp := ErrorResponse{
					Title:  "Not Found",
					Detail: "Resource not found",
				}
				json.NewEncoder(w).Encode(errorResp)
			},
			wantErr:   true,
			wantCount: 0,
			wantNames: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := createMockClient(tt.handler)
			defer server.Close()

			agents, err := GetAgents(client)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, agents)
			} else {
				assert.NoError(t, err)
				// agents can be nil or empty slice - both are valid for empty results
				if tt.wantCount == 0 {
					assert.True(t, agents == nil || len(agents) == 0)
				} else {
					assert.NotNil(t, agents)
					assert.Equal(t, tt.wantCount, len(agents))
					if len(agents) > 0 {
						for i, name := range tt.wantNames {
							if i < len(agents) {
								assert.Equal(t, name, agents[i].Name)
							}
						}
					}
				}
			}
		})
	}
}

func TestGetAgentUUIDs(t *testing.T) {
	tests := []struct {
		name       string
		agentNames []string
		handler    http.HandlerFunc
		wantErr    bool
		wantUUIDs  []string
	}{
		{
			name:       "successful get UUIDs for all agents",
			agentNames: []string{"agent1", "agent2", "agent3"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				response := ConnectorResponse{
					Connectors: []Connector{
						{Name: "agent1", UUIDURL: "uuid1"},
						{Name: "agent2", UUIDURL: "uuid2"},
						{Name: "agent3", UUIDURL: "uuid3"},
					},
				}
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
			},
			wantErr:   false,
			wantUUIDs: []string{"uuid1", "uuid2", "uuid3"},
		},
		{
			name:       "some agents not found",
			agentNames: []string{"agent1", "missing-agent", "agent3"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				response := ConnectorResponse{
					Connectors: []Connector{
						{Name: "agent1", UUIDURL: "uuid1"},
						{Name: "agent3", UUIDURL: "uuid3"},
					},
				}
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
			},
			wantErr:   false,
			wantUUIDs: []string{"uuid1", "uuid3"}, // missing-agent not found
		},
		{
			name:       "empty agent names",
			agentNames: []string{},
			handler: func(w http.ResponseWriter, r *http.Request) {
				response := ConnectorResponse{
					Connectors: []Connector{},
				}
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
			},
			wantErr:   false,
			wantUUIDs: []string{},
		},
		{
			name:       "get agents fails",
			agentNames: []string{"agent1"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErr:   true,
			wantUUIDs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := createMockClient(tt.handler)
			defer server.Close()

			uuids, err := GetAgentUUIDs(client, tt.agentNames)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, uuids)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantUUIDs, uuids)
			}
		})
	}
}

func TestDeleteConnector(t *testing.T) {
	tests := []struct {
		name      string
		uuidURL   string
		handler   http.HandlerFunc
		wantErr   bool
	}{
		{
			name:    "successful delete",
			uuidURL: "test-uuid",
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodDelete, r.Method)
				w.WriteHeader(http.StatusNoContent)
			},
			wantErr: false,
		},
		{
			name:    "successful delete with OK status",
			uuidURL: "test-uuid",
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodDelete, r.Method)
				w.WriteHeader(http.StatusOK)
			},
			wantErr: false,
		},
		{
			name:    "connector not found",
			uuidURL: "non-existent",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				errorResp := ErrorResponse{
					Title:  "Not Found",
					Detail: "Connector not found",
				}
				json.NewEncoder(w).Encode(errorResp)
			},
			wantErr: true,
		},
		{
			name:    "server error",
			uuidURL: "test-uuid",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				errorResp := ErrorResponse{
					Title:  "Internal Server Error",
					Detail: "Something went wrong",
				}
				json.NewEncoder(w).Encode(errorResp)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := createMockClient(tt.handler)
			defer server.Close()

			err := DeleteConnector(client, tt.uuidURL)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAssignAgents(t *testing.T) {
	tests := []struct {
		name      string
		appID     string
		agentNames []string
		handler   http.HandlerFunc
		wantErr   bool
	}{
		{
			name:      "successful assign",
			appID:     "app-123",
			agentNames: []string{"agent1", "agent2"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				// Handle GetAgents call (GET /crux/v1/mgmt-pop/agents)
				if r.URL.Path == "/crux/v1/mgmt-pop/agents" && r.Method == http.MethodGet {
					response := ConnectorResponse{
						Connectors: []Connector{
							{Name: "agent1", UUIDURL: "uuid1"},
							{Name: "agent2", UUIDURL: "uuid2"},
						},
					}
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(response)
					return
				}
				
				// Handle AssignAgents call (POST /crux/v1/mgmt-pop/apps/{appID}/agents)
				if r.Method == http.MethodPost {
					w.WriteHeader(http.StatusOK)
					return
				}
			},
			wantErr: false,
		},
		{
			name:      "no agents to assign",
			appID:     "app-123",
			agentNames: []string{},
			handler: func(w http.ResponseWriter, r *http.Request) {
				// GetAgentUUIDs still calls GetAgents even with empty agentNames
				if r.URL.Path == "/crux/v1/mgmt-pop/agents" && r.Method == http.MethodGet {
					response := ConnectorResponse{
						Connectors: []Connector{},
					}
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(response)
					return
				}
				// No AssignAgents call since no agents to assign
				w.WriteHeader(http.StatusOK)
			},
			wantErr: false, // No error, just no-op
		},
		{
			name:      "agent not found",
			appID:     "app-123",
			agentNames: []string{"missing-agent"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				response := ConnectorResponse{
					Connectors: []Connector{},
				}
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
			},
			wantErr: false, // No error, just empty agents list
		},
		{
			name:      "server error on assign",
			appID:     "app-123",
			agentNames: []string{"agent1"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/crux/v1/mgmt-pop/agents" && r.Method == http.MethodGet {
					response := ConnectorResponse{
						Connectors: []Connector{
							{Name: "agent1", UUIDURL: "uuid1"},
						},
					}
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(response)
					return
				}
				w.WriteHeader(http.StatusInternalServerError)
				errorResp := ErrorResponse{
					Title:  "Internal Server Error",
					Detail: "Failed to assign agents",
				}
				json.NewEncoder(w).Encode(errorResp)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := createMockClient(tt.handler)
			defer server.Close()

			assignReq := AssignAgents{
				AppId:      tt.appID,
				AgentNames: tt.agentNames,
			}

			err := assignReq.AssignAgents(context.Background(), client)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetAppAgents(t *testing.T) {
	tests := []struct {
		name      string
		app       Application
		handler   http.HandlerFunc
		wantErr   bool
		wantNames []string
	}{
		{
			name: "successful get app agents",
			app:   Application{UUIDURL: "app-123"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodGet, r.Method)
				response := AppAgentResponse{
					Agents: []struct {
						Agent struct {
							Name    string `json:"name,omitempty"`
							UUIDURL string `json:"uuid_url,omitempty"`
						} `json:"agent,omitempty"`
						ResourceURI struct {
							Href string `json:"href,omitempty"`
						} `json:"resource_uri,omitempty"`
					}{
						{Agent: struct {
							Name    string `json:"name,omitempty"`
							UUIDURL string `json:"uuid_url,omitempty"`
						}{Name: "agent1", UUIDURL: "uuid1"}},
						{Agent: struct {
							Name    string `json:"name,omitempty"`
							UUIDURL string `json:"uuid_url,omitempty"`
						}{Name: "agent2", UUIDURL: "uuid2"}},
					},
				}
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
			},
			wantErr:   false,
			wantNames: []string{"agent1", "agent2"},
		},
		{
			name: "empty agents list",
			app:   Application{UUIDURL: "app-123"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				response := AppAgentResponse{
					Agents: []struct {
						Agent struct {
							Name    string `json:"name,omitempty"`
							UUIDURL string `json:"uuid_url,omitempty"`
						} `json:"agent,omitempty"`
						ResourceURI struct {
							Href string `json:"href,omitempty"`
						} `json:"resource_uri,omitempty"`
					}{},
				}
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
			},
			wantErr:   false,
			wantNames: []string{},
		},
		{
			name: "server error",
			app:   Application{UUIDURL: "app-123"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				errorResp := ErrorResponse{
					Title:  "Internal Server Error",
					Detail: "Something went wrong",
				}
				json.NewEncoder(w).Encode(errorResp)
			},
			wantErr:   true,
			wantNames: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := createMockClient(tt.handler)
			defer server.Close()

			agentNames, err := tt.app.GetAppAgents(client)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, agentNames)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantNames, agentNames)
			}
		})
	}
}

func TestUnAssignAgents(t *testing.T) {
	tests := []struct {
		name      string
		appID     string
		agentNames []string
		handler   http.HandlerFunc
		wantErr   bool
	}{
		{
			name:      "successful unassign",
			appID:     "app-123",
			agentNames: []string{"agent1", "agent2"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				// Handle GetAgents call (GET /crux/v1/mgmt-pop/agents)
				if r.URL.Path == "/crux/v1/mgmt-pop/agents" && r.Method == http.MethodGet {
					response := ConnectorResponse{
						Connectors: []Connector{
							{Name: "agent1", UUIDURL: "uuid1"},
							{Name: "agent2", UUIDURL: "uuid2"},
						},
					}
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(response)
					return
				}
				
				// Handle UnAssignAgents call (POST with method=delete query param)
				if r.Method == http.MethodPost {
					w.WriteHeader(http.StatusOK)
					return
				}
				
				w.WriteHeader(http.StatusOK)
			},
			wantErr: false,
		},
		{
			name:      "no agents to unassign",
			appID:     "app-123",
			agentNames: []string{},
			handler: func(w http.ResponseWriter, r *http.Request) {
				// GetAgentUUIDs still calls GetAgents even with empty agentNames
				if r.URL.Path == "/crux/v1/mgmt-pop/agents" && r.Method == http.MethodGet {
					response := ConnectorResponse{
						Connectors: []Connector{},
					}
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(response)
					return
				}
				// No UnAssignAgents call since no agents to unassign
				w.WriteHeader(http.StatusOK)
			},
			wantErr: false, // No error, just no-op
		},
		{
			name:      "server error on unassign",
			appID:     "app-123",
			agentNames: []string{"agent1"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				// Handle GetAgents call
				if r.URL.Path == "/crux/v1/mgmt-pop/agents" && r.Method == http.MethodGet {
					response := ConnectorResponse{
						Connectors: []Connector{
							{Name: "agent1", UUIDURL: "uuid1"},
						},
					}
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(response)
					return
				}
				// Handle UnAssignAgents call with error
				if r.Method == http.MethodPost {
					w.WriteHeader(http.StatusInternalServerError)
					errorResp := ErrorResponse{
						Title:  "Internal Server Error",
						Detail: "Failed to unassign agents",
					}
					json.NewEncoder(w).Encode(errorResp)
					return
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := createMockClient(tt.handler)
			defer server.Close()

			assignReq := AssignAgents{
				AppId:      tt.appID,
				AgentNames: tt.agentNames,
			}

			err := assignReq.UnAssignAgents(context.Background(), client)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

