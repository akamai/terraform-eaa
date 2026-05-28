// pkg/client/connectorpool_test.go
package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
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
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
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
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
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
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
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
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
