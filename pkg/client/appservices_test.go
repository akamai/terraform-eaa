package client

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestACLSetting_Validate(t *testing.T) {
	tests := map[string]struct {
		setting ACLSetting
		wantErr bool
	}{
		"valid_is": {
			setting: ACLSetting{Operator: "==", Type: "url", Value: "/test"},
		},
		"valid_is_not": {
			setting: ACLSetting{Operator: "!=", Type: "country", Value: "US"},
		},
		"invalid_operator": {
			setting: ACLSetting{Operator: ">", Type: "url", Value: "/test"},
			wantErr: true,
		},
		"invalid_type": {
			setting: ACLSetting{Operator: "==", Type: "invalid", Value: "/test"},
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := tt.setting.Validate()
			requireErrIs(t, err, tt.wantErr, nil)
		})
	}
}

func TestAccessRule_IsEqual(t *testing.T) {
	rule1 := AccessRule{
		Name:   "rule-1",
		Status: 1,
		Settings: []ACLSetting{
			{Operator: "==", Type: "url", Value: "/test"},
		},
	}
	rule2 := AccessRule{
		Name:   "rule-1",
		Status: 1,
		Settings: []ACLSetting{
			{Operator: "==", Type: "url", Value: "/test"},
		},
	}
	rule3 := AccessRule{
		Name:   "rule-different",
		Status: 0,
		Settings: []ACLSetting{
			{Operator: "!=", Type: "country", Value: "US"},
		},
	}

	tests := map[string]struct {
		a    AccessRule
		b    AccessRule
		want bool
	}{
		"equal":            {a: rule1, b: rule2, want: true},
		"different_status": {a: rule1, b: rule3, want: false},
		"different_settings_count": {
			a:    rule1,
			b:    AccessRule{Status: 1, Settings: []ACLSetting{}},
			want: false,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.a.IsEqual(tt.b))
		})
	}
}

// ---------------------------------------------------------------------------
// CreateAccessRule
// ---------------------------------------------------------------------------

func TestCreateAccessRule(t *testing.T) {
	ctx := context.Background()
	serviceUUID := "svc-uuid-123"

	t.Run("success", func(t *testing.T) {
		router := newPathRouter(t)
		router.Handle("POST", "/crux/v1/mgmt-pop/services/"+serviceUUID+"/rules",
			jsonHandler(http.StatusOK, map[string]string{"status": "created"}))

		ec := newTestClient(t, router)
		rule := AccessRule{
			Name:   "test-rule",
			Status: ADMIN_STATE_ENABLED,
			Settings: []ACLSetting{
				{Operator: "==", Type: "url", Value: "/test"},
			},
		}

		err := rule.CreateAccessRule(ctx, ec, serviceUUID)
		require.NoError(t, err)
	})

	t.Run("empty_service_uuid", func(t *testing.T) {
		ec := newTestClient(t, http.NotFoundHandler())
		rule := AccessRule{Name: "test-rule"}

		err := rule.CreateAccessRule(ctx, ec, "")
		require.Error(t, err)
	})

	t.Run("api_error", func(t *testing.T) {
		router := newPathRouter(t)
		router.Handle("POST", "/crux/v1/mgmt-pop/services/"+serviceUUID+"/rules",
			errorJSONHandler(http.StatusBadRequest, "bad request"))

		ec := newTestClient(t, router)
		rule := AccessRule{Name: "test-rule", Status: 1}

		err := rule.CreateAccessRule(ctx, ec, serviceUUID)
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// DeleteAccessRule
// ---------------------------------------------------------------------------

func TestDeleteAccessRule(t *testing.T) {
	ctx := context.Background()
	serviceUUID := "svc-uuid-123"
	ruleUUID := "rule-uuid-456"

	t.Run("success", func(t *testing.T) {
		router := newPathRouter(t)
		router.Handle("DELETE", "/crux/v1/mgmt-pop/services/"+serviceUUID+"/rules/"+ruleUUID,
			jsonHandler(http.StatusOK, nil))

		ec := newTestClient(t, router)
		rule := AccessRule{UUID_URL: ruleUUID}

		err := rule.DeleteAccessRule(ctx, ec, serviceUUID)
		require.NoError(t, err)
	})

	t.Run("empty_rule_uuid", func(t *testing.T) {
		ec := newTestClient(t, http.NotFoundHandler())
		rule := AccessRule{UUID_URL: ""}

		err := rule.DeleteAccessRule(ctx, ec, serviceUUID)
		require.Error(t, err)
	})

	t.Run("empty_service_uuid", func(t *testing.T) {
		ec := newTestClient(t, http.NotFoundHandler())
		rule := AccessRule{UUID_URL: ruleUUID}

		err := rule.DeleteAccessRule(ctx, ec, "")
		require.Error(t, err)
	})

	t.Run("api_error", func(t *testing.T) {
		router := newPathRouter(t)
		router.Handle("DELETE", "/crux/v1/mgmt-pop/services/"+serviceUUID+"/rules/"+ruleUUID,
			errorJSONHandler(http.StatusInternalServerError, "server error"))

		ec := newTestClient(t, router)
		rule := AccessRule{UUID_URL: ruleUUID}

		err := rule.DeleteAccessRule(ctx, ec, serviceUUID)
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// ModifyAccessRule
// ---------------------------------------------------------------------------

func TestModifyAccessRule(t *testing.T) {
	ctx := context.Background()
	serviceUUID := "svc-uuid-123"
	ruleUUID := "rule-uuid-456"

	t.Run("success", func(t *testing.T) {
		router := newPathRouter(t)
		router.Handle("PUT", "/crux/v1/mgmt-pop/services/"+serviceUUID+"/rules/"+ruleUUID,
			jsonHandler(http.StatusOK, nil))

		ec := newTestClient(t, router)
		rule := AccessRule{
			UUID_URL: ruleUUID,
			Name:     "modified-rule",
			Status:   ADMIN_STATE_ENABLED,
			Settings: []ACLSetting{
				{Operator: "!=", Type: "country", Value: "US"},
			},
		}

		err := rule.ModifyAccessRule(ctx, ec, serviceUUID)
		require.NoError(t, err)
	})

	t.Run("empty_rule_uuid", func(t *testing.T) {
		ec := newTestClient(t, http.NotFoundHandler())
		rule := AccessRule{UUID_URL: ""}

		err := rule.ModifyAccessRule(ctx, ec, serviceUUID)
		require.Error(t, err)
	})

	t.Run("empty_service_uuid", func(t *testing.T) {
		ec := newTestClient(t, http.NotFoundHandler())
		rule := AccessRule{UUID_URL: ruleUUID}

		err := rule.ModifyAccessRule(ctx, ec, "")
		require.Error(t, err)
	})

	t.Run("api_error", func(t *testing.T) {
		router := newPathRouter(t)
		router.Handle("PUT", "/crux/v1/mgmt-pop/services/"+serviceUUID+"/rules/"+ruleUUID,
			errorJSONHandler(http.StatusBadRequest, "bad request"))

		ec := newTestClient(t, router)
		rule := AccessRule{UUID_URL: ruleUUID, Name: "test", Status: 1}

		err := rule.ModifyAccessRule(ctx, ec, serviceUUID)
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// EnableService
// ---------------------------------------------------------------------------

func TestEnableService(t *testing.T) {
	serviceUUID := "svc-uuid-123"

	t.Run("success", func(t *testing.T) {
		router := newPathRouter(t)
		router.Handle("PUT", "/crux/v1/mgmt-pop/services/"+serviceUUID,
			jsonHandler(http.StatusOK, nil))

		ec := newTestClient(t, router)
		svc := AppService{UUIDURL: serviceUUID, Name: "access", Status: "enabled"}

		err := svc.EnableService(context.Background(), ec)
		require.NoError(t, err)
	})

	t.Run("empty_uuid", func(t *testing.T) {
		ec := newTestClient(t, http.NotFoundHandler())
		svc := AppService{UUIDURL: ""}

		err := svc.EnableService(context.Background(), ec)
		require.Error(t, err)
	})

	t.Run("api_error", func(t *testing.T) {
		router := newPathRouter(t)
		router.Handle("PUT", "/crux/v1/mgmt-pop/services/"+serviceUUID,
			errorJSONHandler(http.StatusInternalServerError, "error"))

		ec := newTestClient(t, router)
		svc := AppService{UUIDURL: serviceUUID}

		err := svc.EnableService(context.Background(), ec)
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// GetACLService
// ---------------------------------------------------------------------------

func TestGetACLService(t *testing.T) {
	appUUID := "app-uuid-123"

	t.Run("success", func(t *testing.T) {
		router := newPathRouter(t)
		router.Handle("GET", "/crux/v1/mgmt-pop/apps/"+appUUID+"/services",
			jsonHandler(http.StatusOK, AppServicesResponse{
				AppServices: []AppServiceData{
					{
						Service: AppService{
							Name:        "access",
							UUIDURL:     "svc-uuid-456",
							ServiceType: SERVICE_TYPE_ACCESS_CTRL,
						},
						Status: 1,
					},
				},
			}))

		ec := newTestClient(t, router)
		svc, err := GetACLService(context.Background(), ec, appUUID)
		require.NoError(t, err)
		require.NotNil(t, svc)
		assert.Equal(t, "svc-uuid-456", svc.UUIDURL)
		assert.Equal(t, SERVICE_TYPE_ACCESS_CTRL, svc.ServiceType)
	})

	t.Run("empty_uuid", func(t *testing.T) {
		ec := newTestClient(t, http.NotFoundHandler())

		svc, err := GetACLService(context.Background(), ec, "")
		require.Error(t, err)
		assert.Nil(t, svc)
	})

	t.Run("no_access_service_found", func(t *testing.T) {
		router := newPathRouter(t)
		router.Handle("GET", "/crux/v1/mgmt-pop/apps/"+appUUID+"/services",
			jsonHandler(http.StatusOK, AppServicesResponse{
				AppServices: []AppServiceData{
					{
						Service: AppService{
							Name:        "other",
							UUIDURL:     "svc-other",
							ServiceType: 99,
						},
					},
				},
			}))

		ec := newTestClient(t, router)
		svc, err := GetACLService(context.Background(), ec, appUUID)
		require.Error(t, err)
		assert.Nil(t, svc)
	})

	t.Run("api_error", func(t *testing.T) {
		router := newPathRouter(t)
		router.Handle("GET", "/crux/v1/mgmt-pop/apps/"+appUUID+"/services",
			errorJSONHandler(http.StatusInternalServerError, "error"))

		ec := newTestClient(t, router)
		svc, err := GetACLService(context.Background(), ec, appUUID)
		require.Error(t, err)
		assert.Nil(t, svc)
	})
}

// ---------------------------------------------------------------------------
// ExtractACLService
// ---------------------------------------------------------------------------

func TestExtractACLService(t *testing.T) {
	ctx := context.Background()

	buildResourceData := func(t *testing.T, services []interface{}) *schema.ResourceData {
		t.Helper()
		resourceSchema := map[string]*schema.Schema{
			"service": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"service_type": {Type: schema.TypeString, Required: true},
						"status":       {Type: schema.TypeString, Required: true},
						"access_rule": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name":   {Type: schema.TypeString, Required: true},
									"status": {Type: schema.TypeString, Optional: true},
									"rule": {
										Type:     schema.TypeList,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"operator": {Type: schema.TypeString, Required: true},
												"type":     {Type: schema.TypeString, Required: true},
												"value":    {Type: schema.TypeString, Required: true},
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
		d := schema.TestResourceDataRaw(t, resourceSchema, map[string]interface{}{
			"service": services,
		})
		return d
	}

	t.Run("valid_access_service", func(t *testing.T) {
		services := []interface{}{
			map[string]interface{}{
				"service_type": "access",
				"status":       "enabled",
				"access_rule": []interface{}{
					map[string]interface{}{
						"name":   "block-us",
						"status": "on",
						"rule": []interface{}{
							map[string]interface{}{
								"operator": "==",
								"type":     "country",
								"value":    "US",
							},
						},
					},
				},
			},
		}

		ec := newTestClient(t, http.NotFoundHandler())
		d := buildResourceData(t, services)

		aclSvc, err := ExtractACLService(ctx, d, ec)
		require.NoError(t, err)
		require.NotNil(t, aclSvc)
		assert.Equal(t, "enabled", aclSvc.Status)
		require.Len(t, aclSvc.ACLRules, 1)
		assert.Equal(t, "block-us", aclSvc.ACLRules[0].Name)
		assert.Equal(t, ADMIN_STATE_ENABLED, aclSvc.ACLRules[0].Status)
		require.Len(t, aclSvc.ACLRules[0].Settings, 1)
		assert.Equal(t, "==", aclSvc.ACLRules[0].Settings[0].Operator)
	})

	t.Run("rule_status_off", func(t *testing.T) {
		services := []interface{}{
			map[string]interface{}{
				"service_type": "access",
				"status":       "disabled",
				"access_rule": []interface{}{
					map[string]interface{}{
						"name":   "test-rule",
						"status": "off",
						"rule": []interface{}{
							map[string]interface{}{
								"operator": "!=",
								"type":     "url",
								"value":    "/admin",
							},
						},
					},
				},
			},
		}

		ec := newTestClient(t, http.NotFoundHandler())
		d := buildResourceData(t, services)

		aclSvc, err := ExtractACLService(ctx, d, ec)
		require.NoError(t, err)
		require.NotNil(t, aclSvc)
		assert.Equal(t, ADMIN_STATE_DISABLED, aclSvc.ACLRules[0].Status)
	})

	t.Run("invalid_rule_type_rejected", func(t *testing.T) {
		services := []interface{}{
			map[string]interface{}{
				"service_type": "access",
				"status":       "enabled",
				"access_rule": []interface{}{
					map[string]interface{}{
						"name":   "bad-rule",
						"status": "on",
						"rule": []interface{}{
							map[string]interface{}{
								"operator": "==",
								"type":     "invalid_type",
								"value":    "test",
							},
						},
					},
				},
			},
		}

		ec := newTestClient(t, http.NotFoundHandler())
		d := buildResourceData(t, services)

		_, err := ExtractACLService(ctx, d, ec)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid rule configuration")
	})

	t.Run("non_access_service_skipped", func(t *testing.T) {
		services := []interface{}{
			map[string]interface{}{
				"service_type": "wapp",
				"status":       "enabled",
				"access_rule":  []interface{}{},
			},
		}

		ec := newTestClient(t, http.NotFoundHandler())
		d := buildResourceData(t, services)

		aclSvc, err := ExtractACLService(ctx, d, ec)
		require.NoError(t, err)
		require.NotNil(t, aclSvc)
		assert.Empty(t, aclSvc.ACLRules)
	})
}

// ---------------------------------------------------------------------------
// GetAccessControlRules
// ---------------------------------------------------------------------------

func TestGetAccessControlRules(t *testing.T) {
	serviceUUID := "svc-uuid-123"

	t.Run("success", func(t *testing.T) {
		router := newPathRouter(t)
		router.Handle("GET", "/crux/v1/mgmt-pop/services/"+serviceUUID+"/rules",
			jsonHandler(http.StatusOK, ACLRulesResponse{
				ACLRules: []AccessRule{
					{Name: "rule-1", UUID_URL: "rule-uuid-1", Status: 1},
				},
			}))

		ec := newTestClient(t, router)
		resp, err := GetAccessControlRules(context.Background(), ec, serviceUUID)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Len(t, resp.ACLRules, 1)
		assert.Equal(t, "rule-1", resp.ACLRules[0].Name)
	})

	t.Run("empty_service_uuid", func(t *testing.T) {
		ec := newTestClient(t, http.NotFoundHandler())
		resp, err := GetAccessControlRules(context.Background(), ec, "")
		require.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("api_error", func(t *testing.T) {
		router := newPathRouter(t)
		router.Handle("GET", "/crux/v1/mgmt-pop/services/"+serviceUUID+"/rules",
			errorJSONHandler(http.StatusInternalServerError, "error"))

		ec := newTestClient(t, router)
		resp, err := GetAccessControlRules(context.Background(), ec, serviceUUID)
		require.Error(t, err)
		assert.Nil(t, resp)
	})
}

// ---------------------------------------------------------------------------
// CreateAccessRule request body validation
// ---------------------------------------------------------------------------

func TestCreateAccessRule_RequestBody(t *testing.T) {
	ctx := context.Background()
	serviceUUID := "svc-uuid-123"

	var capturedBody AccessRuleRequest
	router := newPathRouter(t)
	router.Handle("POST", "/crux/v1/mgmt-pop/services/"+serviceUUID+"/rules",
		func(w http.ResponseWriter, r *http.Request) {
			err := json.NewDecoder(r.Body).Decode(&capturedBody)
			require.NoError(t, err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"}) //nolint:errcheck // test helper, response encoding errors are not meaningful here
		})

	ec := newTestClient(t, router)
	rule := AccessRule{
		Name:   "my-rule",
		Status: ADMIN_STATE_ENABLED,
		Settings: []ACLSetting{
			{Operator: "==", Type: "url", Value: "/secret"},
		},
	}

	err := rule.CreateAccessRule(ctx, ec, serviceUUID)
	require.NoError(t, err)

	assert.Equal(t, "my-rule", capturedBody.Name)
	assert.Equal(t, RULE_ACTION_DENY, capturedBody.Action)
	assert.Equal(t, RULE_TYPE_ACCESS_CTRL, capturedBody.RuleType)
	assert.Equal(t, serviceUUID, capturedBody.Service)
	assert.True(t, capturedBody.MergeGlobal)
	assert.False(t, capturedBody.GlobalRule)
	require.Len(t, capturedBody.Settings, 1)
	assert.Equal(t, "url", capturedBody.Settings[0].Type)
}
