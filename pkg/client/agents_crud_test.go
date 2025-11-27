package client

import (
	"context"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
)

// Helper function to convert string to *string for tests
func stringPtrHelper(s string) *string {
	return &s
}

func TestCreateConnectorRequest_CreateConnectorRequestFromSchema(t *testing.T) {
	testCases := []struct {
		name           string
		resourceData   map[string]interface{}
		expectError    bool
		errorContains  string
		validateResult func(*testing.T, *CreateConnectorRequest)
	}{
		{
			name: "successful create connector request with all fields",
			resourceData: map[string]interface{}{
				"name":                    "Test Connector",
				"description":             "Test connector description",
				"status":                  1,
				"auth_service":            true,
				"data_service":            true,
				"debug_channel_permitted": true,
				"package":                 "vmware",
			},
			expectError: false,
			validateResult: func(t *testing.T, ccr *CreateConnectorRequest) {
				assert.Equal(t, "Test Connector", ccr.Name)
				assert.NotNil(t, ccr.Description)
				assert.Equal(t, "Test connector description", *ccr.Description)
				assert.Equal(t, 1, ccr.Status)
				assert.True(t, ccr.AuthService)
				assert.True(t, ccr.DataService)
				assert.True(t, ccr.DebugChannelPermitted)
				assert.Equal(t, int(AGENT_PACKAGE_VMWARE), ccr.Package)
			},
		},
		{
			name: "create connector request with minimal fields",
			resourceData: map[string]interface{}{
				"name":    "Minimal Connector",
				"package": "vmware",
			},
			expectError: false,
			validateResult: func(t *testing.T, ccr *CreateConnectorRequest) {
				assert.Equal(t, "Minimal Connector", ccr.Name)
				assert.Nil(t, ccr.Description)
				assert.Equal(t, 1, ccr.Status) // STATE_ENABLED default
				assert.Equal(t, int(AGENT_PACKAGE_VMWARE), ccr.Package)
			},
		},
		{
			name: "create connector request with AWS package",
			resourceData: map[string]interface{}{
				"name":    "AWS Connector",
				"package": "aws",
			},
			expectError: false,
			validateResult: func(t *testing.T, ccr *CreateConnectorRequest) {
				assert.Equal(t, "AWS Connector", ccr.Name)
				assert.Equal(t, int(AGENT_PACKAGE_AWS), ccr.Package)
			},
		},
		{
			name: "create connector request with Docker package",
			resourceData: map[string]interface{}{
				"name":    "Docker Connector",
				"package": "docker",
			},
			expectError: false,
			validateResult: func(t *testing.T, ccr *CreateConnectorRequest) {
				assert.Equal(t, "Docker Connector", ccr.Name)
				assert.Equal(t, int(AGENT_PACKAGE_DOCKER), ccr.Package)
			},
		},
		{
			name: "create connector request with Azure package",
			resourceData: map[string]interface{}{
				"name":    "Azure Connector",
				"package": "azure",
			},
			expectError: false,
			validateResult: func(t *testing.T, ccr *CreateConnectorRequest) {
				assert.Equal(t, "Azure Connector", ccr.Name)
				assert.Equal(t, int(AGENT_PACKAGE_AZURE), ccr.Package)
			},
		},
		{
			name: "connector with debug enabled and AWS package",
			resourceData: map[string]interface{}{
				"name":                    "debug-connector",
				"description":             "debug connector description",
				"debug_channel_permitted": true,
				"package":                 "aws",
			},
			expectError: false,
			validateResult: func(t *testing.T, ccr *CreateConnectorRequest) {
				assert.Equal(t, "debug-connector", ccr.Name)
				assert.NotNil(t, ccr.Description)
				assert.Equal(t, "debug connector description", *ccr.Description)
				assert.True(t, ccr.DebugChannelPermitted)
				assert.Equal(t, int(AGENT_PACKAGE_AWS), ccr.Package)
			},
		},
		{
			name: "missing name field",
			resourceData: map[string]interface{}{
				"description": "Connector without name",
				"package":     "vmware",
			},
			expectError:   true,
			errorContains: "invalid value for a key",
		},
		{
			name: "empty name field",
			resourceData: map[string]interface{}{
				"name":    "",
				"package": "vmware",
			},
			expectError:   true,
			errorContains: "invalid value for a key",
		},
		{
			name: "invalid package type",
			resourceData: map[string]interface{}{
				"name":    "Test Connector",
				"package": "invalid_package",
			},
			expectError:   true,
			errorContains: "invalid value for a key",
		},
		{
			name: "missing package field",
			resourceData: map[string]interface{}{
				"name": "Test Connector",
			},
			expectError:   true,
			errorContains: "invalid value for a key",
		},
		{
			name: "empty description string",
			resourceData: map[string]interface{}{
				"name":        "Test Connector",
				"description": "",
				"package":     "vmware",
			},
			expectError: false,
			validateResult: func(t *testing.T, ccr *CreateConnectorRequest) {
				assert.Equal(t, "Test Connector", ccr.Name)
				assert.Nil(t, ccr.Description) // Empty string should result in nil
				assert.Equal(t, int(AGENT_PACKAGE_VMWARE), ccr.Package)
			},
		},
		{
			name: "debug_channel_permitted false",
			resourceData: map[string]interface{}{
				"name":                    "Test Connector",
				"debug_channel_permitted": false,
				"package":                 "vmware",
			},
			expectError: false,
			validateResult: func(t *testing.T, ccr *CreateConnectorRequest) {
				assert.Equal(t, "Test Connector", ccr.Name)
				assert.False(t, ccr.DebugChannelPermitted)
				assert.Equal(t, int(AGENT_PACKAGE_VMWARE), ccr.Package)
			},
		},
		{
			name: "create connector request with VBox package",
			resourceData: map[string]interface{}{
				"name":    "VBox Connector",
				"package": "vbox",
			},
			expectError: false,
			validateResult: func(t *testing.T, ccr *CreateConnectorRequest) {
				assert.Equal(t, "VBox Connector", ccr.Name)
				assert.Equal(t, int(AGENT_PACKAGE_VBOX), ccr.Package)
			},
		},
		{
			name: "create connector request with KVM package",
			resourceData: map[string]interface{}{
				"name":    "KVM Connector",
				"package": "kvm",
			},
			expectError: false,
			validateResult: func(t *testing.T, ccr *CreateConnectorRequest) {
				assert.Equal(t, "KVM Connector", ccr.Name)
				assert.Equal(t, int(AGENT_PACKAGE_KVM), ccr.Package)
			},
		},
		{
			name: "create connector request with HyperV package",
			resourceData: map[string]interface{}{
				"name":    "HyperV Connector",
				"package": "hyperv",
			},
			expectError: false,
			validateResult: func(t *testing.T, ccr *CreateConnectorRequest) {
				assert.Equal(t, "HyperV Connector", ccr.Name)
				assert.Equal(t, int(AGENT_PACKAGE_HYPERV), ccr.Package)
			},
		},
		{
			name: "create connector request with AWS Classic package",
			resourceData: map[string]interface{}{
				"name":    "AWS Classic Connector",
				"package": "aws_classic",
			},
			expectError: false,
			validateResult: func(t *testing.T, ccr *CreateConnectorRequest) {
				assert.Equal(t, "AWS Classic Connector", ccr.Name)
				assert.Equal(t, int(AGENT_PACKAGE_AWS_CLASSIC), ccr.Package)
			},
		},
		{
			name: "create connector request with Google package",
			resourceData: map[string]interface{}{
				"name":    "Google Connector",
				"package": "google",
			},
			expectError: false,
			validateResult: func(t *testing.T, ccr *CreateConnectorRequest) {
				assert.Equal(t, "Google Connector", ccr.Name)
				assert.Equal(t, int(AGENT_PACKAGE_GOOGLE), ccr.Package)
			},
		},
		{
			name: "create connector request with SoftLayer package",
			resourceData: map[string]interface{}{
				"name":    "SoftLayer Connector",
				"package": "softlayer",
			},
			expectError: false,
			validateResult: func(t *testing.T, ccr *CreateConnectorRequest) {
				assert.Equal(t, "SoftLayer Connector", ccr.Name)
				assert.Equal(t, int(AGENT_PACKAGE_SOFTLAYER), ccr.Package)
			},
		},
		{
			name: "create connector request with Fujitsu K5 package",
			resourceData: map[string]interface{}{
				"name":    "Fujitsu K5 Connector",
				"package": "fujitsu_k5",
			},
			expectError: false,
			validateResult: func(t *testing.T, ccr *CreateConnectorRequest) {
				assert.Equal(t, "Fujitsu K5 Connector", ccr.Name)
				assert.Equal(t, int(AGENT_PACKAGE_FUJITSU_K5), ccr.Package)
			},
		},
		{
			name: "connector with advanced_settings and network_info",
			resourceData: map[string]interface{}{
				"name":    "Connector with Advanced Settings",
				"package": "vmware",
				"advanced_settings": []interface{}{
					map[string]interface{}{
						"network_info": []interface{}{"192.168.1.0/24", "10.0.0.0/8"},
					},
				},
			},
			expectError: false,
			validateResult: func(t *testing.T, ccr *CreateConnectorRequest) {
				assert.Equal(t, "Connector with Advanced Settings", ccr.Name)
				assert.Equal(t, int(AGENT_PACKAGE_VMWARE), ccr.Package)
				assert.NotNil(t, ccr.AdvancedSettings)
				assert.Equal(t, []string{"192.168.1.0/24", "10.0.0.0/8"}, ccr.AdvancedSettings.Network_Info)
			},
		},
		{
			name: "connector with advanced_settings and empty network_info",
			resourceData: map[string]interface{}{
				"name":    "Connector with Empty Network Info",
				"package": "vmware",
				"advanced_settings": []interface{}{
					map[string]interface{}{
						"network_info": []interface{}{},
					},
				},
			},
			expectError: false,
			validateResult: func(t *testing.T, ccr *CreateConnectorRequest) {
				assert.Equal(t, "Connector with Empty Network Info", ccr.Name)
				assert.Equal(t, int(AGENT_PACKAGE_VMWARE), ccr.Package)
				assert.NotNil(t, ccr.AdvancedSettings)
				// Empty network_info should default to 0.0.0.0/0
				assert.Equal(t, []string{"0.0.0.0/0"}, ccr.AdvancedSettings.Network_Info)
			},
		},
		{
			name: "connector without advanced_settings",
			resourceData: map[string]interface{}{
				"name":    "Connector without Advanced Settings",
				"package": "vmware",
			},
			expectError: false,
			validateResult: func(t *testing.T, ccr *CreateConnectorRequest) {
				assert.Equal(t, "Connector without Advanced Settings", ccr.Name)
				assert.Equal(t, int(AGENT_PACKAGE_VMWARE), ccr.Package)
				// Should default to 0.0.0.0/0
				assert.NotNil(t, ccr.AdvancedSettings)
				assert.Equal(t, []string{"0.0.0.0/0"}, ccr.AdvancedSettings.Network_Info)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create resource data
			resourceSchema := map[string]*schema.Schema{
				"name": {
					Type:     schema.TypeString,
					Required: true,
				},
				"description": {
					Type:     schema.TypeString,
					Optional: true,
				},
				"status": {
					Type:     schema.TypeInt,
					Optional: true,
				},
				"auth_service": {
					Type:     schema.TypeBool,
					Optional: true,
				},
				"data_service": {
					Type:     schema.TypeBool,
					Optional: true,
				},
				"debug_channel_permitted": {
					Type:     schema.TypeBool,
					Optional: true,
				},
				"package": {
					Type:     schema.TypeString,
					Optional: true,
				},
				"advanced_settings": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"network_info": {
								Type:     schema.TypeList,
								Optional: true,
								Elem: &schema.Schema{
									Type: schema.TypeString,
								},
							},
						},
					},
				},
			}

			d := schema.TestResourceDataRaw(t, resourceSchema, tc.resourceData)

			// Create client
			logger := hclog.NewNullLogger()
			client := &EaaClient{
				Logger: logger,
			}

			// Execute function
			ctx := context.Background()
			ccr := &CreateConnectorRequest{}
			err := ccr.CreateConnectorRequestFromSchema(ctx, d, client)

			// Assertions
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				assert.NoError(t, err)
				if tc.validateResult != nil {
					tc.validateResult(t, ccr)
				}
			}
		})
	}
}
