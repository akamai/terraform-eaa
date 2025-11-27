package client

import (
	"context"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
)

// TestCreateConnectorPoolRequestFromSchema tests schema to request conversion
func TestCreateConnectorPoolRequestFromSchema(t *testing.T) {
	tests := map[string]struct {
		resourceData  map[string]interface{}
		expectError   bool
		errorContains string
		validateFunc  func(*testing.T, *CreateConnectorPoolRequest)
	}{
		"successful conversion with all fields": {
			resourceData: map[string]interface{}{
				"name":          "test-pool",
				"description":   "Test description",
				"package_type":  "vmware",
				"infra_type":    "eaa",
				"operating_mode": "connector",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.Equal(t, "test-pool", req.Name)
				assert.Equal(t, "Test description", req.Description)
				assert.Equal(t, 1, req.PackageType) // vmware
				assert.NotNil(t, req.InfraType)
				assert.Equal(t, 1, *req.InfraType) // eaa
				assert.NotNil(t, req.OperatingMode)
				assert.Equal(t, 1, *req.OperatingMode) // connector
			},
		},
		"successful conversion with minimal fields": {
			resourceData: map[string]interface{}{
				"name":         "minimal-pool",
				"package_type": "vmware",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.Equal(t, "minimal-pool", req.Name)
				assert.Equal(t, "", req.Description)
				assert.Equal(t, 1, req.PackageType)
				assert.Nil(t, req.InfraType)
				assert.Nil(t, req.OperatingMode)
			},
		},
		"successful conversion with optional description": {
			resourceData: map[string]interface{}{
				"name":         "pool-with-desc",
				"description":  "Optional description",
				"package_type": "aws",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.Equal(t, "pool-with-desc", req.Name)
				assert.Equal(t, "Optional description", req.Description)
				assert.Equal(t, 3, req.PackageType) // aws = 3 (vmware=1, vbox=2, aws=3)
			},
		},
		"missing required name": {
			resourceData: map[string]interface{}{
				"package_type": "vmware",
			},
			expectError:   true,
			errorContains: "'name' is required but missing",
		},
		"empty string for name": {
			resourceData: map[string]interface{}{
				"name":         "",
				"package_type": "vmware",
			},
			expectError:   true,
			errorContains: "'name' is required but missing", // Terraform treats empty strings as missing
		},
		"missing required package_type": {
			resourceData: map[string]interface{}{
				"name": "test-pool",
			},
			expectError:   true,
			errorContains: "'package_type' is required but missing",
		},
		"empty string for package_type": {
			resourceData: map[string]interface{}{
				"name":         "test-pool",
				"package_type": "",
			},
			expectError:   true,
			errorContains: "'package_type' is required but missing", // Terraform treats empty strings as missing
		},
		"invalid package_type": {
			resourceData: map[string]interface{}{
				"name":         "test-pool",
				"package_type": "invalid-package",
			},
			expectError:   true,
			errorContains: "invalid package_type",
		},
		"invalid infra_type": {
			resourceData: map[string]interface{}{
				"name":         "test-pool",
				"package_type": "vmware",
				"infra_type":   "invalid-infra",
			},
			expectError:   true,
			errorContains: "invalid infra_type",
		},
		"invalid operating_mode": {
			resourceData: map[string]interface{}{
				"name":           "test-pool",
				"package_type":   "vmware",
				"operating_mode": "invalid-mode",
			},
			expectError:   true,
			errorContains: "invalid operating_mode",
		},
		"package_type_vmware": {
			resourceData: map[string]interface{}{
				"name":         "test-pool",
				"package_type": "vmware",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.Equal(t, 1, req.PackageType) // vmware = 1
			},
		},
		"package_type_vbox": {
			resourceData: map[string]interface{}{
				"name":         "test-pool",
				"package_type": "vbox",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.Equal(t, 2, req.PackageType) // vbox = 2
			},
		},
		"package_type_aws": {
			resourceData: map[string]interface{}{
				"name":         "test-pool",
				"package_type": "aws",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.Equal(t, 3, req.PackageType) // aws = 3
			},
		},
		"package_type_kvm": {
			resourceData: map[string]interface{}{
				"name":         "test-pool",
				"package_type": "kvm",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.Equal(t, 4, req.PackageType) // kvm = 4
			},
		},
		"package_type_hyperv": {
			resourceData: map[string]interface{}{
				"name":         "test-pool",
				"package_type": "hyperv",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.Equal(t, 5, req.PackageType) // hyperv = 5
			},
		},
		"package_type_docker": {
			resourceData: map[string]interface{}{
				"name":         "test-pool",
				"package_type": "docker",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.Equal(t, 6, req.PackageType) // docker = 6
			},
		},
		"package_type_aws_classic": {
			resourceData: map[string]interface{}{
				"name":         "test-pool",
				"package_type": "aws_classic",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.Equal(t, 7, req.PackageType) // aws_classic = 7
			},
		},
		"package_type_azure": {
			resourceData: map[string]interface{}{
				"name":         "test-pool",
				"package_type": "azure",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.Equal(t, 8, req.PackageType) // azure = 8
			},
		},
		"package_type_google": {
			resourceData: map[string]interface{}{
				"name":         "test-pool",
				"package_type": "google",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.Equal(t, 9, req.PackageType) // google = 9
			},
		},
		"package_type_softlayer": {
			resourceData: map[string]interface{}{
				"name":         "test-pool",
				"package_type": "softlayer",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.Equal(t, 10, req.PackageType) // softlayer = 10
			},
		},
		"package_type_fujitsu_k5": {
			resourceData: map[string]interface{}{
				"name":         "test-pool",
				"package_type": "fujitsu_k5",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.Equal(t, 11, req.PackageType) // fujitsu_k5 = 11
			},
		},
		"infra_type_eaa": {
			resourceData: map[string]interface{}{
				"name":         "test-pool",
				"package_type": "vmware",
				"infra_type":   "eaa",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.NotNil(t, req.InfraType)
				assert.Equal(t, 1, *req.InfraType) // eaa = 1
			},
		},
		"infra_type_unified": {
			resourceData: map[string]interface{}{
				"name":         "test-pool",
				"package_type": "vmware",
				"infra_type":   "unified",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.NotNil(t, req.InfraType)
				assert.Equal(t, 2, *req.InfraType) // unified = 2
			},
		},
		"infra_type_broker": {
			resourceData: map[string]interface{}{
				"name":         "test-pool",
				"package_type": "vmware",
				"infra_type":   "broker",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.NotNil(t, req.InfraType)
				assert.Equal(t, 3, *req.InfraType) // broker = 3
			},
		},
		"infra_type_cpag": {
			resourceData: map[string]interface{}{
				"name":         "test-pool",
				"package_type": "vmware",
				"infra_type":   "cpag",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.NotNil(t, req.InfraType)
				assert.Equal(t, 4, *req.InfraType) // cpag = 4
			},
		},
		"operating_mode_connector": {
			resourceData: map[string]interface{}{
				"name":           "test-pool",
				"package_type":   "vmware",
				"operating_mode": "connector",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.NotNil(t, req.OperatingMode)
				assert.Equal(t, 1, *req.OperatingMode) // connector = 1
			},
		},
		"operating_mode_peb": {
			resourceData: map[string]interface{}{
				"name":           "test-pool",
				"package_type":   "vmware",
				"operating_mode": "peb",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.NotNil(t, req.OperatingMode)
				assert.Equal(t, 2, *req.OperatingMode) // peb = 2
			},
		},
		"operating_mode_combined": {
			resourceData: map[string]interface{}{
				"name":           "test-pool",
				"package_type":   "vmware",
				"operating_mode": "combined",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.NotNil(t, req.OperatingMode)
				assert.Equal(t, 3, *req.OperatingMode) // combined = 3
			},
		},
		"operating_mode_cpag_public": {
			resourceData: map[string]interface{}{
				"name":           "test-pool",
				"package_type":   "vmware",
				"operating_mode": "cpag_public",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.NotNil(t, req.OperatingMode)
				assert.Equal(t, 4, *req.OperatingMode) // cpag_public = 4
			},
		},
		"operating_mode_cpag_private": {
			resourceData: map[string]interface{}{
				"name":           "test-pool",
				"package_type":   "vmware",
				"operating_mode": "cpag_private",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.NotNil(t, req.OperatingMode)
				assert.Equal(t, 5, *req.OperatingMode) // cpag_private = 5
			},
		},
		"operating_mode_connector_with_china_acceleration": {
			resourceData: map[string]interface{}{
				"name":           "test-pool",
				"package_type":   "vmware",
				"operating_mode": "connector_with_china_acceleration",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.NotNil(t, req.OperatingMode)
				assert.Equal(t, 6, *req.OperatingMode) // connector_with_china_acceleration = 6
			},
		},
		"empty_string_for_description": {
			resourceData: map[string]interface{}{
				"name":         "test-pool",
				"package_type": "vmware",
				"description":  "",
			},
			expectError: false,
			validateFunc: func(t *testing.T, req *CreateConnectorPoolRequest) {
				assert.Equal(t, "", req.Description) // Empty string is valid
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Create resource data
			d := schema.TestResourceDataRaw(t, map[string]*schema.Schema{
				"name":           {Type: schema.TypeString, Required: true},
				"description":    {Type: schema.TypeString, Optional: true},
				"package_type":   {Type: schema.TypeString, Required: true},
				"infra_type":     {Type: schema.TypeString, Optional: true},
				"operating_mode": {Type: schema.TypeString, Optional: true},
			}, tt.resourceData)

			// Create client
			client := &EaaClient{
				Logger: hclog.NewNullLogger(),
			}

			// Create request
			req := &CreateConnectorPoolRequest{}
			err := req.CreateConnectorPoolRequestFromSchema(context.Background(), d, client)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				if tt.validateFunc != nil {
					tt.validateFunc(t, req)
				}
			}
		})
	}
}

