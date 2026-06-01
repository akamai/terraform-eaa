// pkg/client/connectorpool_test.go
package client

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConvertPackageType(t *testing.T) {
	ec := newTestClient(t, jsonHandler(http.StatusOK, nil))

	tests := map[string]struct {
		input   string
		want    int
		wantErr bool
	}{
		"vmware":  {input: "vmware", want: int(AGENT_PACKAGE_VMWARE)},
		"docker":  {input: "docker", want: int(AGENT_PACKAGE_DOCKER)},
		"empty":   {input: "", wantErr: true},
		"invalid": {input: "bad", wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := convertPackageType(tt.input, ec)
			if requireErr(t, err, tt.wantErr) {
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConvertInfraType(t *testing.T) {
	ec := newTestClient(t, jsonHandler(http.StatusOK, nil))

	tests := map[string]struct {
		input   string
		want    int
		wantErr bool
	}{
		"eaa":     {input: "eaa", want: int(INFRA_TYPE_EAA)},
		"unified": {input: "unified", want: int(INFRA_TYPE_UNIFIED)},
		"broker":  {input: "broker", want: int(INFRA_TYPE_BROKER)},
		"cpag":    {input: "cpag", want: int(INFRA_TYPE_CPAG)},
		"empty":   {input: "", wantErr: true},
		"invalid": {input: "bad", wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := convertInfraType(tt.input, ec)
			if requireErr(t, err, tt.wantErr) {
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConvertOperatingMode(t *testing.T) {
	ec := newTestClient(t, jsonHandler(http.StatusOK, nil))

	tests := map[string]struct {
		input   string
		want    int
		wantErr bool
	}{
		"connector":                         {input: "connector", want: int(OPERATING_MODE_CONNECTOR)},
		"peb":                               {input: "peb", want: int(OPERATING_MODE_PEB)},
		"combined":                          {input: "combined", want: int(OPERATING_MODE_COMBINED)},
		"cpag_public":                       {input: "cpag_public", want: int(OPERATING_MODE_CPAG_PUBLIC)},
		"cpag_private":                      {input: "cpag_private", want: int(OPERATING_MODE_CPAG_PRIVATE)},
		"connector_with_china_acceleration": {input: "connector_with_china_acceleration", want: int(OPERATING_MODE_CONNECTOR_WITH_CHINA_ACCELERATION)},
		"empty":                             {input: "", wantErr: true},
		"invalid":                           {input: "bad", wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := convertOperatingMode(tt.input, ec)
			if requireErr(t, err, tt.wantErr) {
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCreateConnectorPool(t *testing.T) {
	poolResp := CreateConnectorPoolResponse{
		UUIDURL: "pool-uuid-1",
		CIDRs:   []string{"10.0.0.0/8"},
	}

	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, poolResp),
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusBadRequest, "bad request"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)

			req := &CreateConnectorPoolRequest{
				Name:        "test-pool",
				Description: "test",
				PackageType: int(AGENT_PACKAGE_DOCKER),
			}
			// CreateConnectorPool is a method on *CreateConnectorPoolRequest
			got, err := req.CreateConnectorPool(nil, ec)
			if requireErr(t, err, tt.wantErr) {
				return
			}
			assert.Equal(t, "pool-uuid-1", got.UUIDURL)
		})
	}
}

func TestDeleteConnectorPool(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusNoContent, nil),
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusNotFound, "not found"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)

			// DeleteConnectorPool is a standalone function: (ctx, ec, uuid)
			err := DeleteConnectorPool(nil, ec, "pool-uuid-1")
			if requireErr(t, err, tt.wantErr) {
				return
			}
		})
	}
}

func TestGetConnectorPool(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(200, ConnectorPool{
				Name:    "test-pool",
				UUIDURL: "pool-uuid-123",
			}),
		},
		"api_error": {
			handler: errorJSONHandler(500, "internal error"),
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			router := newPathRouter(t)
			router.Handle("GET", "/crux/v1/mgmt-pop/connector-pools/pool-uuid-123", tc.handler)
			ec := newTestClient(t, router)

			got, err := GetConnectorPool(context.Background(), ec, "pool-uuid-123")
			if requireErr(t, err, tc.wantErr) {
				return
			}
			assert.Equal(t, "test-pool", got.Name)
			assert.Equal(t, "pool-uuid-123", got.UUIDURL)
		})
	}
}

func TestAssignConnectorsToPool(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(200, nil),
		},
		"api_error": {
			handler: errorJSONHandler(500, "assignment failed"),
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			router := newPathRouter(t)
			router.Handle("PUT", "/crux/v1/zt/connector-pools/pool-uuid/agents/associate", tc.handler)
			ec := newTestClient(t, router)

			err := AssignConnectorsToPool(ec, "pool-uuid", []string{"conn-1", "conn-2"})
			if requireErr(t, err, tc.wantErr) {
				return
			}
		})
	}
}

func TestUnassignConnectorsFromPool(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(200, nil),
		},
		"api_error": {
			handler: errorJSONHandler(500, "unassignment failed"),
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			router := newPathRouter(t)
			router.Handle("PUT", "/crux/v1/zt/connector-pools/pool-uuid/agents/disassociate", tc.handler)
			ec := newTestClient(t, router)

			err := UnassignConnectorsFromPool(ec, "pool-uuid", []string{"conn-1"})
			if requireErr(t, err, tc.wantErr) {
				return
			}
		})
	}
}

func TestGetConnectorsInPool(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		want    []string
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(200, ConnectorPool{
				Connectors: json.RawMessage(`[{"uuid_url":"conn-1"},{"uuid_url":"conn-2"}]`),
			}),
			want: []string{"conn-1", "conn-2"},
		},
		"empty_connectors": {
			handler: jsonHandler(200, ConnectorPool{}),
			want:    nil,
		},
		"api_error": {
			handler: errorJSONHandler(500, "server error"),
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			router := newPathRouter(t)
			router.Handle("GET", "/crux/v1/mgmt-pop/connector-pools/pool-uuid", tc.handler)
			ec := newTestClient(t, router)

			got, err := GetConnectorsInPool(ec, "pool-uuid")
			if requireErr(t, err, tc.wantErr) {
				return
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestGetAppsAssignedToPool(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		want    []string
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(200, ConnectorPool{
				Applications: json.RawMessage(`[{"uuid_url":"app-1"},{"uuid_url":"app-2"}]`),
			}),
			want: []string{"app-1", "app-2"},
		},
		"no_apps": {
			handler: jsonHandler(200, ConnectorPool{}),
			want:    nil,
		},
		"api_error": {
			handler: errorJSONHandler(500, "server error"),
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			router := newPathRouter(t)
			router.Handle("GET", "/crux/v1/mgmt-pop/connector-pools/pool-uuid", tc.handler)
			ec := newTestClient(t, router)

			got, err := GetAppsAssignedToPool(ec, "pool-uuid")
			if requireErr(t, err, tc.wantErr) {
				return
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestAssignConnectorPoolsToApp(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(200, nil),
		},
		"api_error": {
			handler: errorJSONHandler(500, "assignment failed"),
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			router := newPathRouter(t)
			router.Handle("PUT", "/crux/v1/mgmt-pop/apps/app-uuid/connector-pools/associate", tc.handler)
			ec := newTestClient(t, router)

			req := &AppConnectorPoolAssignmentRequest{
				Add: AppConnectorPoolAssignment{
					Active: []string{"pool-1"},
				},
			}
			err := AssignConnectorPoolsToApp(ec, "app-uuid", req)
			if requireErr(t, err, tc.wantErr) {
				return
			}
		})
	}
}
