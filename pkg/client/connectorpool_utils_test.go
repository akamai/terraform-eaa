package client

import (
	"errors"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestConvertPackageType(t *testing.T) {
	// Create a simple EaaClient with logger for testing
	ec := &EaaClient{
		Logger: hclog.Default(),
	}

	tests := []struct {
		name        string
		packageType string
		expected    int
		hasError    bool
	}{
		{
			name:        "VMware package type",
			packageType: string(ConnPackageTypeVmware),
			expected:    int(AGENT_PACKAGE_VMWARE),
			hasError:    false,
		},
		{
			name:        "AWS package type",
			packageType: string(ConnPackageTypeAWS),
			expected:    int(AGENT_PACKAGE_AWS),
			hasError:    false,
		},
		{
			name:        "Docker package type",
			packageType: string(ConnPackageTypeDocker),
			expected:    int(AGENT_PACKAGE_DOCKER),
			hasError:    false,
		},
		{
			name:        "Azure package type",
			packageType: string(ConnPackageTypeAzure),
			expected:    int(AGENT_PACKAGE_AZURE),
			hasError:    false,
		},
		{
			name:        "VBox package type",
			packageType: string(ConnPackageTypeVbox),
			expected:    int(AGENT_PACKAGE_VBOX),
			hasError:    false,
		},
		{
			name:        "KVM package type",
			packageType: string(ConnPackageTypeKVM),
			expected:    int(AGENT_PACKAGE_KVM),
			hasError:    false,
		},
		{
			name:        "HyperV package type",
			packageType: string(ConnPackageTypeHyperv),
			expected:    int(AGENT_PACKAGE_HYPERV),
			hasError:    false,
		},
		{
			name:        "AWS Classic package type",
			packageType: string(ConnPackageTypeAWSClassic),
			expected:    int(AGENT_PACKAGE_AWS_CLASSIC),
			hasError:    false,
		},
		{
			name:        "Google package type",
			packageType: string(ConnPackageTypeGoogle),
			expected:    int(AGENT_PACKAGE_GOOGLE),
			hasError:    false,
		},
		{
			name:        "SoftLayer package type",
			packageType: string(ConnPackageTypeSoftLayer),
			expected:    int(AGENT_PACKAGE_SOFTLAYER),
			hasError:    false,
		},
		{
			name:        "Fujitsu K5 package type",
			packageType: string(ConnPackageTypeFujitsu_k5),
			expected:    int(AGENT_PACKAGE_FUJITSU_K5),
			hasError:    false,
		},
		{
			name:        "empty package type",
			packageType: "",
			expected:    0,
			hasError:    true,
		},
		{
			name:        "invalid package type",
			packageType: "invalid",
			expected:    0,
			hasError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := convertPackageType(tt.packageType, ec)

			if tt.hasError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("expected %d, got %d", tt.expected, result)
				}
			}
		})
	}
}

func TestConvertInfraType(t *testing.T) {
	// Create a simple EaaClient with logger for testing
	ec := &EaaClient{
		Logger: hclog.Default(),
	}

	tests := []struct {
		name      string
		infraType string
		expected  int
		hasError  bool
	}{
		{
			name:      "EAA infra type",
			infraType: string(InfraTypeEAA),
			expected:  int(INFRA_TYPE_EAA),
			hasError:  false,
		},
		{
			name:      "Unified infra type",
			infraType: string(InfraTypeUnified),
			expected:  int(INFRA_TYPE_UNIFIED),
			hasError:  false,
		},
		{
			name:      "Broker infra type",
			infraType: string(InfraTypeBroker),
			expected:  int(INFRA_TYPE_BROKER),
			hasError:  false,
		},
		{
			name:      "CPAG infra type",
			infraType: string(InfraTypeCPAG),
			expected:  int(INFRA_TYPE_CPAG),
			hasError:  false,
		},
		{
			name:      "empty infra type",
			infraType: "",
			expected:  0,
			hasError:  true,
		},
		{
			name:      "invalid infra type",
			infraType: "invalid",
			expected:  0,
			hasError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := convertInfraType(tt.infraType, ec)

			if tt.hasError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("expected %d, got %d", tt.expected, result)
				}
			}
		})
	}
}

func TestConvertOperatingMode(t *testing.T) {
	// Create a simple EaaClient with logger for testing
	ec := &EaaClient{
		Logger: hclog.Default(),
	}

	tests := []struct {
		name          string
		operatingMode string
		expected      int
		hasError      bool
	}{
		{
			name:          "Connector operating mode",
			operatingMode: string(OperatingModeConnector),
			expected:      int(OPERATING_MODE_CONNECTOR),
			hasError:      false,
		},
		{
			name:          "PEB operating mode",
			operatingMode: string(OperatingModePEB),
			expected:      int(OPERATING_MODE_PEB),
			hasError:      false,
		},
		{
			name:          "Combined operating mode",
			operatingMode: string(OperatingModeCombined),
			expected:      int(OPERATING_MODE_COMBINED),
			hasError:      false,
		},
		{
			name:          "CPAG Public operating mode",
			operatingMode: string(OperatingModeCPAGPublic),
			expected:      int(OPERATING_MODE_CPAG_PUBLIC),
			hasError:      false,
		},
		{
			name:          "CPAG Private operating mode",
			operatingMode: string(OperatingModeCPAGPrivate),
			expected:      int(OPERATING_MODE_CPAG_PRIVATE),
			hasError:      false,
		},
		{
			name:          "Connector with China Acceleration",
			operatingMode: string(OperatingModeConnectorWithChinaAccel),
			expected:      int(OPERATING_MODE_CONNECTOR_WITH_CHINA_ACCELERATION),
			hasError:      false,
		},
		{
			name:          "empty operating mode",
			operatingMode: "",
			expected:      0,
			hasError:      true,
		},
		{
			name:          "invalid operating mode",
			operatingMode: "invalid",
			expected:      0,
			hasError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := convertOperatingMode(tt.operatingMode, ec)

			if tt.hasError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("expected %d, got %d", tt.expected, result)
				}
			}
		})
	}
}

func TestValidateAndConvertEnumField(t *testing.T) {
	// Create a simple EaaClient with logger for testing
	ec := &EaaClient{
		Logger: hclog.Default(),
	}

	// Mock converter function for testing
	mockConverter := func(value string, ec *EaaClient) (int, error) {
		if value == "valid" {
			return 123, nil
		}
		return 0, errors.New("invalid value")
	}

	tests := []struct {
		name         string
		fieldName    string
		resourceData map[string]interface{}
		expected     *int
		hasError     bool
	}{
		{
			name:      "valid field conversion",
			fieldName: "test_field",
			resourceData: map[string]interface{}{
				"test_field": "valid",
			},
			expected: func() *int { i := 123; return &i }(),
			hasError: false,
		},
		{
			name:      "field not present",
			fieldName: "missing_field",
			resourceData: map[string]interface{}{
				"other_field": "value",
			},
			expected: nil,
			hasError: false,
		},
		{
			name:      "field wrong type",
			fieldName: "test_field",
			resourceData: map[string]interface{}{
				"test_field": 123, // Should be string
			},
			expected: nil,
			hasError: true,
		},
		{
			name:      "converter returns error",
			fieldName: "test_field",
			resourceData: map[string]interface{}{
				"test_field": "invalid",
			},
			expected: nil,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock ResourceData
			schemaMap := map[string]*schema.Schema{
				"test_field":  {Type: schema.TypeString},
				"other_field": {Type: schema.TypeString},
			}

			// Use schema.InternalMap to set up the ResourceData properly
			config := schema.TestResourceDataRaw(t, schemaMap, tt.resourceData)

			result, err := validateAndConvertEnumField(config, tt.fieldName, mockConverter, ec)

			if tt.hasError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if tt.expected == nil && result != nil {
					t.Errorf("expected nil, got %v", result)
				} else if tt.expected != nil && result == nil {
					t.Errorf("expected %v, got nil", *tt.expected)
				} else if tt.expected != nil && result != nil && *tt.expected != *result {
					t.Errorf("expected %d, got %d", *tt.expected, *result)
				}
			}
		})
	}
}
