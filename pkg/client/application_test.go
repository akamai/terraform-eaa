package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// CreateMinimalApplication
// ---------------------------------------------------------------------------

func TestCreateMinimalApplication(t *testing.T) {
	wantResp := ApplicationResponse{
		Name:    "my-app",
		UUIDURL: "abc-123",
	}

	successHandler, captured := jsonHandlerWithCapture(http.StatusOK, wantResp)

	tests := map[string]struct {
		errIs    error
		handler  http.HandlerFunc
		captured *bytes.Buffer
		mcar     *MinimalCreateAppRequest
		check    func(t *testing.T, got *ApplicationResponse)
		wantErr  bool
	}{
		"success": {
			handler:  successHandler,
			captured: captured,
			mcar: &MinimalCreateAppRequest{
				Name:          "my-app",
				AppProfile:    1,
				AppType:       1,
				ClientAppMode: 1,
			},
			check: func(t *testing.T, got *ApplicationResponse) {
				require.NotNil(t, got)
				assert.Equal(t, "my-app", got.Name)
				assert.Equal(t, "abc-123", got.UUIDURL)
			},
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusBadRequest, "bad request"),
			mcar: &MinimalCreateAppRequest{
				Name:          "bad-app",
				AppProfile:    1,
				AppType:       1,
				ClientAppMode: 1,
			},
			wantErr: true,
			errIs:   ErrAppCreate,
			check: func(t *testing.T, got *ApplicationResponse) {
				assert.Nil(t, got)
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			got, err := tt.mcar.CreateMinimalApplication(context.Background(), ec)
			if requireErrIs(t, err, tt.wantErr, tt.errIs) {
				if tt.check != nil {
					tt.check(t, got)
				}
				return
			}
			if tt.check != nil {
				tt.check(t, got)
			}
			if tt.captured != nil {
				var reqBody map[string]interface{}
				require.NoError(t, json.Unmarshal(tt.captured.Bytes(), &reqBody), "request body should be valid JSON")
				assert.Equal(t, "my-app", reqBody["name"], "request body should contain the Name field")
			}
		})
	}
}

func TestCreateMinimalApplication_MalformedJSON(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{invalid json`)) //nolint:errcheck // test helper, error handling not needed
	}
	ec := newTestClient(t, http.HandlerFunc(handler))

	mcar := &MinimalCreateAppRequest{
		Name:          "my-app",
		AppProfile:    1,
		AppType:       1,
		ClientAppMode: 1,
	}
	got, err := mcar.CreateMinimalApplication(context.Background(), ec)
	require.Error(t, err, "malformed JSON should produce an error")
	assert.Nil(t, got)
}

// ---------------------------------------------------------------------------
// DeployApplication
// ---------------------------------------------------------------------------

func TestDeployApplication(t *testing.T) {
	tests := map[string]struct {
		errIs   error
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, nil),
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "deploy failed"),
			wantErr: true,
			errIs:   ErrDeploy,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			router := newPathRouter(t)
			router.Handle("POST", "/crux/v1/mgmt-pop/apps/app-uuid-1/deploy", tt.handler)
			ec := newTestClient(t, router)

			app := &Application{UUIDURL: "app-uuid-1"}
			err := app.DeployApplication(context.Background(), ec)
			if requireErrIs(t, err, tt.wantErr, tt.errIs) {
				return
			}
		})
	}
}

// ---------------------------------------------------------------------------
// DeleteApplication
// ---------------------------------------------------------------------------

func TestDeleteApplication(t *testing.T) {
	tests := map[string]struct {
		errIs   error
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, nil),
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusForbidden, "forbidden"),
			wantErr: true,
			errIs:   ErrAppDelete,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			router := newPathRouter(t)
			router.Handle("DELETE", "/crux/v1/mgmt-pop/apps/app-uuid-2", tt.handler)
			ec := newTestClient(t, router)

			app := &Application{UUIDURL: "app-uuid-2"}
			err := app.DeleteApplication(context.Background(), ec)
			if requireErrIs(t, err, tt.wantErr, tt.errIs) {
				return
			}
		})
	}
}

// ---------------------------------------------------------------------------
// UpdateApplication
// ---------------------------------------------------------------------------

func TestUpdateApplication(t *testing.T) {
	tests := map[string]struct {
		errIs   error
		handler http.HandlerFunc
		name    string
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, map[string]interface{}{
				"name": "updated-app",
				"advanced_settings": map[string]interface{}{
					"app_auth": "none",
				},
			}),
			name: "updated-app",
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusBadRequest, "bad fields"),
			wantErr: true,
			errIs:   ErrAppUpdate,
		},
	}
	for tName, tt := range tests {
		t.Run(tName, func(t *testing.T) {
			router := newPathRouter(t)
			router.Handle("PUT", "/crux/v1/mgmt-pop/apps/app-uuid-3", tt.handler)
			ec := newTestClient(t, router)

			updateReq := &ApplicationUpdateRequest{}
			updateReq.UUIDURL = "app-uuid-3"
			updateReq.Name = tt.name
			err := updateReq.UpdateApplication(context.Background(), ec)
			if requireErrIs(t, err, tt.wantErr, tt.errIs) {
				return
			}
		})
	}
}

// ---------------------------------------------------------------------------
// UpdateG2O
// ---------------------------------------------------------------------------

func TestUpdateG2O(t *testing.T) {
	wantResp := G2OResponse{
		G2OEnabled: "true",
		G2OKey:     "some-key",
		G2ONonce:   "some-nonce",
	}

	tests := map[string]struct {
		errIs   error
		handler http.HandlerFunc
		check   func(t *testing.T, got *G2OResponse)
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, wantResp),
			check: func(t *testing.T, got *G2OResponse) {
				require.NotNil(t, got)
				assert.Equal(t, "some-key", got.G2OKey)
				assert.Equal(t, "some-nonce", got.G2ONonce)
			},
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "g2o failed"),
			wantErr: true,
			errIs:   ErrAppUpdate,
			check: func(t *testing.T, got *G2OResponse) {
				assert.Nil(t, got)
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			router := newPathRouter(t)
			router.Handle("POST", "/crux/v1/mgmt-pop/apps/app-uuid-4/g2o", tt.handler)
			ec := newTestClient(t, router)

			app := &Application{UUIDURL: "app-uuid-4"}
			got, err := app.UpdateG2O(context.Background(), ec)
			if requireErrIs(t, err, tt.wantErr, tt.errIs) {
				if tt.check != nil {
					tt.check(t, got)
				}
				return
			}
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// UpdateEdgeAuthentication
// ---------------------------------------------------------------------------

func TestUpdateEdgeAuthentication(t *testing.T) {
	wantResp := EdgeAuthResponse{
		EdgeCookieKey: "cookie-key-123",
		SLAObjectURL:  "sla-object-url",
	}

	tests := map[string]struct {
		errIs   error
		handler http.HandlerFunc
		check   func(t *testing.T, got *EdgeAuthResponse)
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, wantResp),
			check: func(t *testing.T, got *EdgeAuthResponse) {
				require.NotNil(t, got)
				assert.Equal(t, "cookie-key-123", got.EdgeCookieKey)
				assert.Equal(t, "sla-object-url", got.SLAObjectURL)
			},
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusBadRequest, "edge auth failed"),
			wantErr: true,
			errIs:   ErrAppUpdate,
			check: func(t *testing.T, got *EdgeAuthResponse) {
				assert.Nil(t, got)
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			router := newPathRouter(t)
			router.Handle("POST", "/crux/v1/mgmt-pop/apps/app-uuid-5/edgekey", tt.handler)
			ec := newTestClient(t, router)

			app := &Application{UUIDURL: "app-uuid-5"}
			got, err := app.UpdateEdgeAuthentication(context.Background(), ec)
			if requireErrIs(t, err, tt.wantErr, tt.errIs) {
				if tt.check != nil {
					tt.check(t, got)
				}
				return
			}
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CreateApplication (full create)
// ---------------------------------------------------------------------------

func TestCreateApplication(t *testing.T) {
	wantResp := ApplicationResponse{
		Name:    "full-app",
		UUIDURL: "full-uuid-1",
	}

	tests := map[string]struct {
		errIs   error
		handler http.HandlerFunc
		car     *CreateAppRequest
		check   func(t *testing.T, got *ApplicationResponse)
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, wantResp),
			car: &CreateAppRequest{
				Name:          "full-app",
				AppType:       1,
				AppProfile:    1,
				ClientAppMode: 1,
			},
			check: func(t *testing.T, got *ApplicationResponse) {
				require.NotNil(t, got)
				assert.Equal(t, "full-app", got.Name)
				assert.Equal(t, "full-uuid-1", got.UUIDURL)
			},
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusBadRequest, "invalid fields"),
			car: &CreateAppRequest{
				Name:          "bad-full-app",
				AppType:       1,
				AppProfile:    1,
				ClientAppMode: 1,
			},
			wantErr: true,
			errIs:   ErrAppCreate,
			check: func(t *testing.T, got *ApplicationResponse) {
				assert.Nil(t, got)
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			got, err := tt.car.CreateApplication(context.Background(), ec)
			if requireErrIs(t, err, tt.wantErr, tt.errIs) {
				if tt.check != nil {
					tt.check(t, got)
				}
				return
			}
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Application.FromResponse
// ---------------------------------------------------------------------------

func TestFromResponse_PopulatedFields(t *testing.T) {
	desc := "test description"
	host := "app.example.com"
	cname := "app.cname.example.com"
	resp := &ApplicationResponse{
		Name:          "my-app",
		Description:   &desc,
		AppProfile:    1,
		AppType:       2,
		ClientAppMode: 3,
		Host:          &host,
		CName:         &cname,
		BookmarkURL:   "https://example.com",
		UUIDURL:       "resp-uuid",
		AppDeployed:   true,
		SAML:          true,
		Oidc:          false,
		WSFED:         false,
	}

	app := Application{}
	app.FromResponse(resp)

	assert.Equal(t, "my-app", app.Name)
	assert.Equal(t, &desc, app.Description)
	assert.Equal(t, 1, app.AppProfile)
	assert.Equal(t, 2, app.AppType)
	assert.Equal(t, 3, app.ClientAppMode)
	assert.Equal(t, &host, app.Host)
	assert.Equal(t, &cname, app.CName)
	assert.Equal(t, "https://example.com", app.BookmarkURL)
	assert.Equal(t, "resp-uuid", app.UUIDURL)
	assert.True(t, app.AppDeployed)
	assert.True(t, app.SAML)
	assert.False(t, app.Oidc)
}

func TestFromResponse_NilPointers(t *testing.T) {
	resp := &ApplicationResponse{
		Name:    "minimal-app",
		UUIDURL: "min-uuid",
	}

	app := Application{}
	app.FromResponse(resp)

	assert.Equal(t, "minimal-app", app.Name)
	assert.Nil(t, app.Description)
	assert.Nil(t, app.Host)
	assert.Nil(t, app.CName)
	assert.Nil(t, app.Cert)
}

// ---------------------------------------------------------------------------
// processCustomDomain
// ---------------------------------------------------------------------------

func TestProcessCustomDomainSkipsWhenHostMissing(t *testing.T) {
	resourceSchema := map[string]*schema.Schema{
		"cert_type": {
			Type:     schema.TypeString,
			Optional: true,
		},
	}

	d := schema.TestResourceDataRaw(t, resourceSchema, map[string]interface{}{})
	ec := &EaaClient{}
	appUpdateReq := &ApplicationUpdateRequest{}

	err := processCustomDomain(context.Background(), ec, appUpdateReq, d)
	assert.NoError(t, err, "expected nil error when host is missing")
}

// ---------------------------------------------------------------------------
// firstMapBlock
// ---------------------------------------------------------------------------

func TestFirstMapBlock_Success(t *testing.T) {
	blocks := []interface{}{
		map[string]interface{}{"key": "value"},
	}
	got, err := firstMapBlock(blocks, "test")
	require.NoError(t, err)
	assert.Equal(t, "value", got["key"])
}

func TestFirstMapBlock_EmptySlice(t *testing.T) {
	_, err := firstMapBlock([]interface{}{}, "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected at least one block")
}

func TestFirstMapBlock_WrongType(t *testing.T) {
	blocks := []interface{}{"not a map"}
	_, err := firstMapBlock(blocks, "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected map[string]interface{}")
}

// ---------------------------------------------------------------------------
// ConfigureAgents
// ---------------------------------------------------------------------------

func TestConfigureAgents(t *testing.T) {
	agentsSchema := map[string]*schema.Schema{
		"agents": {
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},
	}

	tests := map[string]struct {
		setupRouter func(pr *pathRouter)
		agents      []interface{}
		wantErr     bool
	}{
		"success_single_agent": {
			agents: []interface{}{"agent-1"},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/agents", jsonHandler(http.StatusOK, ConnectorResponse{
					Connectors: []Connector{
						{Name: "agent-1", UUIDURL: "uuid-1"},
					},
				}))
				pr.Handle("POST", "/crux/v1/mgmt-pop/apps/app-42/agents", jsonHandler(http.StatusOK, nil))
			},
		},
		"success_multiple_agents": {
			agents: []interface{}{"agent-1", "agent-2"},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/agents", jsonHandler(http.StatusOK, ConnectorResponse{
					Connectors: []Connector{
						{Name: "agent-1", UUIDURL: "uuid-1"},
						{Name: "agent-2", UUIDURL: "uuid-2"},
					},
				}))
				pr.Handle("POST", "/crux/v1/mgmt-pop/apps/app-42/agents", jsonHandler(http.StatusOK, nil))
			},
		},
		"empty_agents": {
			agents: []interface{}{},
			setupRouter: func(pr *pathRouter) {
			},
		},
		"no_agents_key": {
			agents: nil,
			setupRouter: func(pr *pathRouter) {
			},
		},
		"api_error_on_assign": {
			agents: []interface{}{"agent-1"},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/agents", jsonHandler(http.StatusOK, ConnectorResponse{
					Connectors: []Connector{
						{Name: "agent-1", UUIDURL: "uuid-1"},
					},
				}))
				pr.Handle("POST", "/crux/v1/mgmt-pop/apps/app-42/agents",
					errorJSONHandler(http.StatusInternalServerError, "assign failed"))
			},
			wantErr: true,
		},
		"agent_lookup_fails": {
			agents: []interface{}{"nonexistent-agent"},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/agents", jsonHandler(http.StatusOK, ConnectorResponse{
					Connectors: []Connector{
						{Name: "agent-1", UUIDURL: "uuid-1"},
					},
				}))
			},
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			pr := newPathRouter(t)
			tt.setupRouter(pr)
			ec := newTestClient(t, pr)

			values := map[string]interface{}{}
			if tt.agents != nil {
				values["agents"] = tt.agents
			}
			d := schema.TestResourceDataRaw(t, agentsSchema, values)

			err := ConfigureAgents(context.Background(), "app-42", d, ec)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// ConfigureAuthentication
// ---------------------------------------------------------------------------

func TestConfigureAuthentication(t *testing.T) {
	authSchema := map[string]*schema.Schema{
		"auth_enabled": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"app_authentication": {
			Type:     schema.TypeList,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"app_idp": {
						Type:     schema.TypeString,
						Optional: true,
					},
					"app_directories": {
						Type:     schema.TypeList,
						Optional: true,
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"name": {
									Type:     schema.TypeString,
									Optional: true,
								},
								"enable_mfa": {
									Type:     schema.TypeBool,
									Optional: true,
								},
								"app_groups": {
									Type:     schema.TypeList,
									Optional: true,
									Elem:     &schema.Schema{Type: schema.TypeString},
								},
							},
						},
					},
				},
			},
		},
	}

	tests := map[string]struct {
		values      map[string]interface{}
		setupRouter func(pr *pathRouter)
		errContains string
		wantErr     bool
	}{
		"auth_disabled": {
			values: map[string]interface{}{
				"auth_enabled":       "false",
				"app_authentication": []interface{}{},
			},
			setupRouter: func(pr *pathRouter) {},
		},
		"auth_enabled_no_auth_block": {
			values: map[string]interface{}{
				"auth_enabled":       "true",
				"app_authentication": []interface{}{},
			},
			setupRouter: func(pr *pathRouter) {},
		},
		"success_idp_and_directories": {
			values: map[string]interface{}{
				"auth_enabled": "true",
				"app_authentication": []interface{}{
					map[string]interface{}{
						"app_idp": "my-idp",
						"app_directories": []interface{}{
							map[string]interface{}{
								"name":       "my-dir",
								"enable_mfa": false,
								"app_groups": []interface{}{},
							},
						},
					},
				},
			},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/idp", jsonHandler(http.StatusOK, IDPResponse{
					IDPS: []IDPResponseData{
						{Name: "my-idp", UUIDURL: "idp-uuid-1"},
					},
				}))
				pr.Handle("GET", "/crux/v1/mgmt-pop/idp/idp-uuid-1/directories", jsonHandler(http.StatusOK, DirectoryResponse{
					DirectoryList: []DirectoryData{
						{Name: "my-dir", UUID: "dir-uuid-1", Groups: []GroupData{
							{Name: "group-1", UUID_URL: "group-uuid-1"},
						}},
					},
				}))
				pr.Handle("POST", "/crux/v1/mgmt-pop/appidp", jsonHandler(http.StatusOK, nil))
				pr.Handle("POST", "/crux/v1/mgmt-pop/appdirectories", jsonHandler(http.StatusOK, nil))
				pr.Handle("POST", "/crux/v1/mgmt-pop/appgroups", jsonHandler(http.StatusOK, nil))
			},
		},
		"success_idp_only_no_directories": {
			values: map[string]interface{}{
				"auth_enabled": "true",
				"app_authentication": []interface{}{
					map[string]interface{}{
						"app_idp":         "my-idp",
						"app_directories": []interface{}{},
					},
				},
			},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/idp", jsonHandler(http.StatusOK, IDPResponse{
					IDPS: []IDPResponseData{
						{Name: "my-idp", UUIDURL: "idp-uuid-1"},
					},
				}))
				pr.Handle("GET", "/crux/v1/mgmt-pop/idp/idp-uuid-1/directories", jsonHandler(http.StatusOK, DirectoryResponse{
					DirectoryList: []DirectoryData{},
				}))
				pr.Handle("POST", "/crux/v1/mgmt-pop/appidp", jsonHandler(http.StatusOK, nil))
			},
		},
		"idp_lookup_fails": {
			values: map[string]interface{}{
				"auth_enabled": "true",
				"app_authentication": []interface{}{
					map[string]interface{}{
						"app_idp":         "missing-idp",
						"app_directories": []interface{}{},
					},
				},
			},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/idp", jsonHandler(http.StatusOK, IDPResponse{
					IDPS: []IDPResponseData{
						{Name: "other-idp", UUIDURL: "idp-uuid-other"},
					},
				}))
				pr.Handle("GET", "/crux/v1/mgmt-pop/idp/idp-uuid-other/directories", jsonHandler(http.StatusOK, DirectoryResponse{}))
			},
			wantErr:     true,
			errContains: "not found",
		},
		"idp_api_error": {
			values: map[string]interface{}{
				"auth_enabled": "true",
				"app_authentication": []interface{}{
					map[string]interface{}{
						"app_idp":         "my-idp",
						"app_directories": []interface{}{},
					},
				},
			},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/idp",
					errorJSONHandler(http.StatusInternalServerError, "idp service down"))
			},
			wantErr: true,
		},
		"assign_idp_fails": {
			values: map[string]interface{}{
				"auth_enabled": "true",
				"app_authentication": []interface{}{
					map[string]interface{}{
						"app_idp":         "my-idp",
						"app_directories": []interface{}{},
					},
				},
			},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/idp", jsonHandler(http.StatusOK, IDPResponse{
					IDPS: []IDPResponseData{
						{Name: "my-idp", UUIDURL: "idp-uuid-1"},
					},
				}))
				pr.Handle("GET", "/crux/v1/mgmt-pop/idp/idp-uuid-1/directories", jsonHandler(http.StatusOK, DirectoryResponse{}))
				pr.Handle("POST", "/crux/v1/mgmt-pop/appidp",
					errorJSONHandler(http.StatusForbidden, "not authorized"))
			},
			wantErr:     true,
			errContains: "assigning IDP to the app failed",
		},
		"directory_assignment_fails": {
			values: map[string]interface{}{
				"auth_enabled": "true",
				"app_authentication": []interface{}{
					map[string]interface{}{
						"app_idp": "my-idp",
						"app_directories": []interface{}{
							map[string]interface{}{
								"name":       "my-dir",
								"enable_mfa": false,
								"app_groups": []interface{}{},
							},
						},
					},
				},
			},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/idp", jsonHandler(http.StatusOK, IDPResponse{
					IDPS: []IDPResponseData{
						{Name: "my-idp", UUIDURL: "idp-uuid-1"},
					},
				}))
				pr.Handle("GET", "/crux/v1/mgmt-pop/idp/idp-uuid-1/directories", jsonHandler(http.StatusOK, DirectoryResponse{
					DirectoryList: []DirectoryData{
						{Name: "my-dir", UUID: "dir-uuid-1"},
					},
				}))
				pr.Handle("POST", "/crux/v1/mgmt-pop/appidp", jsonHandler(http.StatusOK, nil))
				pr.Handle("POST", "/crux/v1/mgmt-pop/appdirectories",
					errorJSONHandler(http.StatusBadRequest, "directory assign failed"))
			},
			wantErr:     true,
			errContains: "assigning directories to the app failed",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			pr := newPathRouter(t)
			tt.setupRouter(pr)
			ec := newTestClient(t, pr)

			d := schema.TestResourceDataRaw(t, authSchema, tt.values)

			err := ConfigureAuthentication(context.Background(), "app-42", d, ec)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}
			require.NoError(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// ConfigureAdvancedSettings
// ---------------------------------------------------------------------------

func TestConfigureAdvancedSettings(t *testing.T) {
	advancedSchema := map[string]*schema.Schema{
		"name": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"description": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"host": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"auth_enabled": {
			Type:     schema.TypeString,
			Optional: true,
		},
		"advanced_settings": {
			Type:     schema.TypeList,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"app_auth": {
						Type:     schema.TypeString,
						Optional: true,
					},
				},
			},
		},
	}

	appGetResp := ApplicationResponse{
		Name:    "my-app",
		UUIDURL: "app-42",
	}

	tests := map[string]struct {
		setupRouter func(pr *pathRouter)
		values      map[string]interface{}
		wantErr     bool
	}{
		"success": {
			values: map[string]interface{}{
				"name":              "my-app",
				"description":       "",
				"host":              "",
				"auth_enabled":      "false",
				"advanced_settings": []interface{}{},
			},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/apps/app-42", jsonHandler(http.StatusOK, appGetResp))
				pr.Handle("PUT", "/crux/v1/mgmt-pop/apps/app-42", jsonHandler(http.StatusOK, map[string]interface{}{
					"name": "my-app",
				}))
			},
		},
		"get_app_api_error": {
			values: map[string]interface{}{
				"name":              "my-app",
				"description":       "",
				"host":              "",
				"auth_enabled":      "false",
				"advanced_settings": []interface{}{},
			},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/apps/app-42",
					errorJSONHandler(http.StatusNotFound, "app not found"))
			},
			wantErr: true,
		},
		"update_app_api_error": {
			values: map[string]interface{}{
				"name":              "my-app",
				"description":       "",
				"host":              "",
				"auth_enabled":      "false",
				"advanced_settings": []interface{}{},
			},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/apps/app-42", jsonHandler(http.StatusOK, appGetResp))
				pr.Handle("PUT", "/crux/v1/mgmt-pop/apps/app-42",
					errorJSONHandler(http.StatusBadRequest, "bad advanced settings"))
			},
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			pr := newPathRouter(t)
			tt.setupRouter(pr)
			ec := newTestClient(t, pr)

			d := schema.TestResourceDataRaw(t, advancedSchema, tt.values)

			err := ConfigureAdvancedSettings(context.Background(), "app-42", d, ec)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// CreateAppRequestFromSchema / UpdateAppRequestFromSchema (direct unit tests)
// ---------------------------------------------------------------------------

func TestCreateAppRequestFromSchema_Direct(t *testing.T) {
	createSchema := map[string]*schema.Schema{
		"name":              {Type: schema.TypeString, Optional: true},
		"description":       {Type: schema.TypeString, Optional: true},
		"app_type":          {Type: schema.TypeString, Optional: true},
		"app_profile":       {Type: schema.TypeString, Optional: true},
		"client_app_mode":   {Type: schema.TypeString, Optional: true},
		"advanced_settings": {Type: schema.TypeMap, Optional: true},
	}

	ec := &EaaClient{}

	t.Run("success_with_tls_suite_fields", func(t *testing.T) {
		d := schema.TestResourceDataRaw(t, createSchema, map[string]interface{}{
			"name":            "create-app",
			"description":     "desc",
			"app_type":        "enterprise",
			"app_profile":     "http",
			"client_app_mode": "tcp",
			"advanced_settings": map[string]interface{}{
				"app_auth":       "none",
				"tls_suite_type": "custom",
				"tls_suite_name": "my-suite",
			},
		})

		req := &CreateAppRequest{}
		err := req.CreateAppRequestFromSchema(context.Background(), d, ec)
		requireErrIs(t, err, false, nil)
		require.Equal(t, "create-app", req.Name)
		require.NotNil(t, req.Description)
		assert.Equal(t, "desc", *req.Description)
		require.NotNil(t, req.TLSSuiteType)
		assert.Equal(t, 2, *req.TLSSuiteType)
		require.NotNil(t, req.TLSSuiteName)
		assert.Equal(t, "my-suite", *req.TLSSuiteName)
	})

	t.Run("missing_name_fails", func(t *testing.T) {
		d := schema.TestResourceDataRaw(t, createSchema, map[string]interface{}{})
		req := &CreateAppRequest{}
		err := req.CreateAppRequestFromSchema(context.Background(), d, ec)
		requireErrIs(t, err, true, ErrInvalidValue)
	})

	t.Run("invalid_tls_suite_type_fails", func(t *testing.T) {
		d := schema.TestResourceDataRaw(t, createSchema, map[string]interface{}{
			"name": "create-app",
			"advanced_settings": map[string]interface{}{
				"tls_suite_type": "invalid",
			},
		})
		req := &CreateAppRequest{}
		err := req.CreateAppRequestFromSchema(context.Background(), d, ec)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid tls_suite_type value")
	})
}

func TestUpdateAppRequestFromSchema_Direct(t *testing.T) {
	updateSchema := map[string]*schema.Schema{
		"name":        {Type: schema.TypeString, Optional: true},
		"description": {Type: schema.TypeString, Optional: true},
		"host":        {Type: schema.TypeString, Optional: true},
		"domain":      {Type: schema.TypeString, Optional: true},
		"tunnel_internal_hosts": {
			Type:     schema.TypeList,
			Optional: true,
			Elem: &schema.Resource{Schema: map[string]*schema.Schema{
				"host":       {Type: schema.TypeString, Optional: true},
				"port_range": {Type: schema.TypeString, Optional: true},
				"proto_type": {Type: schema.TypeInt, Optional: true},
			}},
		},
		"advanced_settings": {Type: schema.TypeMap, Optional: true},
	}

	ec := &EaaClient{}

	t.Run("success_maps_basic_and_tls_fields", func(t *testing.T) {
		d := schema.TestResourceDataRaw(t, updateSchema, map[string]interface{}{
			"name":        "updated-app",
			"description": "updated-desc",
			"host":        "updated.example.com",
			"domain":      "wapp",
			"tunnel_internal_hosts": []interface{}{
				map[string]interface{}{"host": "10.0.0.2", "port_range": "22", "proto_type": 6},
			},
			"advanced_settings": map[string]interface{}{
				"app_auth":       "none",
				"tls_suite_type": "default",
				"tls_suite_name": "default-suite",
			},
		})

		req := &ApplicationUpdateRequest{}
		err := req.UpdateAppRequestFromSchema(context.Background(), d, ec)
		requireErrIs(t, err, false, nil)
		assert.Equal(t, "updated-app", req.Name)
		require.NotNil(t, req.Description)
		assert.Equal(t, "updated-desc", *req.Description)
		require.NotNil(t, req.Host)
		assert.Equal(t, "updated.example.com", *req.Host)
		assert.Equal(t, "2", req.Domain)
		require.Len(t, req.TunnelInternalHosts, 1)
		assert.Equal(t, "10.0.0.2", req.TunnelInternalHosts[0].Host)
		require.NotNil(t, req.TLSSuiteType)
		assert.Equal(t, 1, *req.TLSSuiteType)
		require.NotNil(t, req.TLSSuiteName)
		assert.Equal(t, "default-suite", *req.TLSSuiteName)
	})

	t.Run("invalid_tls_suite_type_fails", func(t *testing.T) {
		d := schema.TestResourceDataRaw(t, updateSchema, map[string]interface{}{
			"advanced_settings": map[string]interface{}{
				"tls_suite_type": "invalid",
			},
		})
		req := &ApplicationUpdateRequest{}
		err := req.UpdateAppRequestFromSchema(context.Background(), d, ec)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid tls_suite_type value")
	})
}

// ---------------------------------------------------------------------------
// ConfigureService
// ---------------------------------------------------------------------------

func TestConfigureService(t *testing.T) {
	serviceSchema := map[string]*schema.Schema{
		"service": {
			Type:     schema.TypeList,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"service_type": {
						Type:     schema.TypeString,
						Optional: true,
					},
					"status": {
						Type:     schema.TypeString,
						Optional: true,
					},
					"access_rule": {
						Type:     schema.TypeList,
						Optional: true,
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"name": {
									Type:     schema.TypeString,
									Optional: true,
								},
								"status": {
									Type:     schema.TypeString,
									Optional: true,
								},
								"rule": {
									Type:     schema.TypeList,
									Optional: true,
									Elem: &schema.Resource{
										Schema: map[string]*schema.Schema{
											"operator": {
												Type:     schema.TypeString,
												Optional: true,
											},
											"type": {
												Type:     schema.TypeString,
												Optional: true,
											},
											"value": {
												Type:     schema.TypeString,
												Optional: true,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	appServiceResp := AppServicesResponse{
		AppServices: []AppServiceData{
			{
				UUIDURL: "svc-data-uuid",
				Service: AppService{
					Name:        "access",
					Status:      "off",
					UUIDURL:     "svc-uuid-1",
					ServiceType: int(SERVICE_TYPE_ACCESS_CTRL),
				},
			},
		},
	}

	tests := map[string]struct {
		values      map[string]interface{}
		setupRouter func(pr *pathRouter)
		wantErr     bool
	}{
		"no_service_key": {
			values: map[string]interface{}{
				"service": []interface{}{},
			},
			setupRouter: func(pr *pathRouter) {},
		},
		"success_with_rule": {
			values: map[string]interface{}{
				"service": []interface{}{
					map[string]interface{}{
						"service_type": "access",
						"status":       "on",
						"access_rule": []interface{}{
							map[string]interface{}{
								"name":   "block-url",
								"status": "on",
								"rule": []interface{}{
									map[string]interface{}{
										"operator": "==",
										"type":     "url",
										"value":    "/blocked",
									},
								},
							},
						},
					},
				},
			},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/apps/app-42/services", jsonHandler(http.StatusOK, appServiceResp))
				pr.Handle("PUT", "/crux/v1/mgmt-pop/services/svc-uuid-1", jsonHandler(http.StatusOK, nil))
				pr.Handle("POST", "/crux/v1/mgmt-pop/services/svc-uuid-1/rules", jsonHandler(http.StatusOK, nil))
			},
		},
		"success_status_unchanged": {
			values: map[string]interface{}{
				"service": []interface{}{
					map[string]interface{}{
						"service_type": "access",
						"status":       "off",
						"access_rule": []interface{}{
							map[string]interface{}{
								"name":   "rule-1",
								"status": "on",
								"rule": []interface{}{
									map[string]interface{}{
										"operator": "==",
										"type":     "url",
										"value":    "/test",
									},
								},
							},
						},
					},
				},
			},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/apps/app-42/services", jsonHandler(http.StatusOK, appServiceResp))
				pr.Handle("POST", "/crux/v1/mgmt-pop/services/svc-uuid-1/rules", jsonHandler(http.StatusOK, nil))
			},
		},
		"get_acl_service_fails": {
			values: map[string]interface{}{
				"service": []interface{}{
					map[string]interface{}{
						"service_type": "access",
						"status":       "on",
						"access_rule":  []interface{}{},
					},
				},
			},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/apps/app-42/services",
					errorJSONHandler(http.StatusInternalServerError, "services unavailable"))
			},
			wantErr: true,
		},
		"enable_service_fails": {
			values: map[string]interface{}{
				"service": []interface{}{
					map[string]interface{}{
						"service_type": "access",
						"status":       "on",
						"access_rule":  []interface{}{},
					},
				},
			},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/apps/app-42/services", jsonHandler(http.StatusOK, appServiceResp))
				pr.Handle("PUT", "/crux/v1/mgmt-pop/services/svc-uuid-1",
					errorJSONHandler(http.StatusBadRequest, "enable failed"))
			},
			wantErr: true,
		},
		"create_rule_fails": {
			values: map[string]interface{}{
				"service": []interface{}{
					map[string]interface{}{
						"service_type": "access",
						"status":       "off",
						"access_rule": []interface{}{
							map[string]interface{}{
								"name":   "bad-rule",
								"status": "on",
								"rule": []interface{}{
									map[string]interface{}{
										"operator": "==",
										"type":     "url",
										"value":    "/fail",
									},
								},
							},
						},
					},
				},
			},
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/apps/app-42/services", jsonHandler(http.StatusOK, appServiceResp))
				pr.Handle("POST", "/crux/v1/mgmt-pop/services/svc-uuid-1/rules",
					errorJSONHandler(http.StatusInternalServerError, "rule create failed"))
			},
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			pr := newPathRouter(t)
			tt.setupRouter(pr)
			ec := newTestClient(t, pr)

			d := schema.TestResourceDataRaw(t, serviceSchema, tt.values)

			err := ConfigureService(context.Background(), "app-42", d, ec)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
