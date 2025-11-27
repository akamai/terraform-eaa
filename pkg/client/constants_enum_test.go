package client

import (
	"testing"
)

func TestDomain_ToInt(t *testing.T) {
	tests := []struct {
		name     string
		domain   Domain
		expected int
		hasError bool
	}{
		{
			name:     "custom domain",
			domain:   AppDomainCustom,
			expected: int(APP_DOMAIN_CUSTOM),
			hasError: false,
		},
		{
			name:     "wapp domain",
			domain:   AppDomainWapp,
			expected: int(APP_DOMAIN_WAPP),
			hasError: false,
		},
		{
			name:     "unknown domain",
			domain:   Domain("invalid"),
			expected: 0,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.domain.ToInt()

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

func TestAppProfile_ToInt(t *testing.T) {
	tests := []struct {
		name     string
		profile  AppProfile
		expected int
		hasError bool
	}{
		{
			name:     "HTTP profile",
			profile:  AppProfileHTTP,
			expected: int(APP_PROFILE_HTTP),
			hasError: false,
		},
		{
			name:     "SharePoint profile",
			profile:  AppProfileSharePoint,
			expected: int(APP_PROFILE_SHAREPOINT),
			hasError: false,
		},
		{
			name:     "Jira profile",
			profile:  AppProfileJira,
			expected: int(APP_PROFILE_JIRA),
			hasError: false,
		},
		{
			name:     "RDP profile",
			profile:  AppProfileRDP,
			expected: int(APP_PROFILE_RDP),
			hasError: false,
		},
		{
			name:     "VNC profile",
			profile:  AppProfileVNC,
			expected: int(APP_PROFILE_VNC),
			hasError: false,
		},
		{
			name:     "SSH profile",
			profile:  AppProfileSSH,
			expected: int(APP_PROFILE_SSH),
			hasError: false,
		},
		{
			name:     "Jenkins profile",
			profile:  AppProfileJenkins,
			expected: int(APP_PROFILE_JENKINS),
			hasError: false,
		},
		{
			name:     "Confluence profile",
			profile:  AppProfileConfluence,
			expected: int(APP_PROFILE_CONFLUENCE),
			hasError: false,
		},
		{
			name:     "TCP profile",
			profile:  AppProfileTCP,
			expected: int(APP_PROFILE_TCP),
			hasError: false,
		},
		{
			name:     "SMB profile",
			profile:  AppProfileSMB,
			expected: int(APP_PROFILE_SMB),
			hasError: false,
		},
		{
			name:     "unknown profile",
			profile:  AppProfile("invalid"),
			expected: 0,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.profile.ToInt()

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

func TestClientAppMode_ToInt(t *testing.T) {
	tests := []struct {
		name     string
		mode     ClientAppMode
		expected int
		hasError bool
	}{
		{
			name:     "TCP mode",
			mode:     ClientAppModeTCP,
			expected: int(CLIENT_APP_MODE_TCP),
			hasError: false,
		},
		{
			name:     "Tunnel mode",
			mode:     ClientAppModeTunnel,
			expected: int(CLIENT_APP_MODE_TUNNEL),
			hasError: false,
		},
		{
			name:     "unknown mode",
			mode:     ClientAppMode("invalid"),
			expected: 0,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.mode.ToInt()

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

func TestHealthCheckType_ToNumeric(t *testing.T) {
	tests := []struct {
		name     string
		hct      HealthCheckType
		expected string
	}{
		{
			name:     "default health check",
			hct:      HealthCheckTypeDefault,
			expected: "0",
		},
		{
			name:     "HTTP health check",
			hct:      HealthCheckTypeHTTP,
			expected: "1",
		},
		{
			name:     "HTTPS health check",
			hct:      HealthCheckTypeHTTPS,
			expected: "2",
		},
		{
			name:     "TLS health check",
			hct:      HealthCheckTypeTLS,
			expected: "3",
		},
		{
			name:     "SSLv3 health check",
			hct:      HealthCheckTypeSSLv3,
			expected: "4",
		},
		{
			name:     "TCP health check",
			hct:      HealthCheckTypeTCP,
			expected: "5",
		},
		{
			name:     "None health check",
			hct:      HealthCheckTypeNone,
			expected: "6",
		},
		{
			name:     "unknown health check type - numeric string fallback",
			hct:      HealthCheckType("7"),
			expected: "7",
		},
		{
			name:     "unknown health check type - string fallback",
			hct:      HealthCheckType("custom"),
			expected: "custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.hct.ToNumeric()
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestHealthCheckTypeInt_ToDescriptive(t *testing.T) {
	tests := []struct {
		name     string
		hct      HealthCheckTypeInt
		expected string
	}{
		{
			name:     "default health check int",
			hct:      HEALTH_CHECK_TYPE_DEFAULT,
			expected: string(HealthCheckTypeDefault),
		},
		{
			name:     "HTTP health check int",
			hct:      HEALTH_CHECK_TYPE_HTTP,
			expected: string(HealthCheckTypeHTTP),
		},
		{
			name:     "HTTPS health check int",
			hct:      HEALTH_CHECK_TYPE_HTTPS,
			expected: string(HealthCheckTypeHTTPS),
		},
		{
			name:     "TLS health check int",
			hct:      HEALTH_CHECK_TYPE_TLS,
			expected: string(HealthCheckTypeTLS),
		},
		{
			name:     "SSLv3 health check int",
			hct:      HEALTH_CHECK_TYPE_SSLV3,
			expected: string(HealthCheckTypeSSLv3),
		},
		{
			name:     "TCP health check int",
			hct:      HEALTH_CHECK_TYPE_TCP,
			expected: string(HealthCheckTypeTCP),
		},
		{
			name:     "None health check int",
			hct:      HEALTH_CHECK_TYPE_NONE,
			expected: string(HealthCheckTypeNone),
		},
		{
			name:     "unknown health check type int",
			hct:      HealthCheckTypeInt(999),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.hct.ToDescriptive()
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestMapHealthCheckTypeToDescriptive(t *testing.T) {
	tests := []struct {
		name     string
		numeric  string
		expected string
	}{
		{
			name:     "map 0 to default",
			numeric:  "0",
			expected: string(HealthCheckTypeDefault),
		},
		{
			name:     "map 1 to HTTP",
			numeric:  "1",
			expected: string(HealthCheckTypeHTTP),
		},
		{
			name:     "map 2 to HTTPS",
			numeric:  "2",
			expected: string(HealthCheckTypeHTTPS),
		},
		{
			name:     "map 3 to TLS",
			numeric:  "3",
			expected: string(HealthCheckTypeTLS),
		},
		{
			name:     "map 4 to SSLv3",
			numeric:  "4",
			expected: string(HealthCheckTypeSSLv3),
		},
		{
			name:     "map 5 to TCP",
			numeric:  "5",
			expected: string(HealthCheckTypeTCP),
		},
		{
			name:     "map 6 to None",
			numeric:  "6",
			expected: string(HealthCheckTypeNone),
		},
		{
			name:     "unknown numeric value fallback",
			numeric:  "999",
			expected: "999",
		},
		{
			name:     "non-numeric value fallback",
			numeric:  "custom",
			expected: "custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MapHealthCheckTypeToDescriptive(tt.numeric)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestServiceType_ToInt(t *testing.T) {
	tests := []struct {
		name     string
		service  ServiceType
		expected int
		hasError bool
	}{
		{
			name:     "WAF service type",
			service:  ServiceTypeWAF,
			expected: int(SERVICE_TYPE_WAF),
			hasError: false,
		},
		{
			name:     "Acceleration service type",
			service:  ServiceTypeAcceleration,
			expected: int(SERVICE_TYPE_ACCELERATION),
			hasError: false,
		},
		{
			name:     "AV service type",
			service:  ServiceTypeAV,
			expected: int(SERVICE_TYPE_AV),
			hasError: false,
		},
		{
			name:     "IPS service type",
			service:  ServiceTypeIPS,
			expected: int(SERVICE_TYPE_IPS),
			hasError: false,
		},
		{
			name:     "SLB service type",
			service:  ServiceTypeSLB,
			expected: int(SERVICE_TYPE_SLB),
			hasError: false,
		},
		{
			name:     "Access Control service type",
			service:  ServiceTypeAccessCtrl,
			expected: int(SERVICE_TYPE_ACCESS_CTRL),
			hasError: false,
		},
		{
			name:     "Rewrite service type",
			service:  ServiceTypeRewrite,
			expected: int(SERVICE_TYPE_REWRITE),
			hasError: false,
		},
		{
			name:     "unknown service type",
			service:  ServiceType("invalid"),
			expected: 0,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.service.ToInt()

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

func TestInfraType_ToInt(t *testing.T) {
	tests := []struct {
		name     string
		infra    InfraType
		expected int
		hasError bool
	}{
		{
			name:     "EAA infra type",
			infra:    InfraTypeEAA,
			expected: int(INFRA_TYPE_EAA),
			hasError: false,
		},
		{
			name:     "Unified infra type",
			infra:    InfraTypeUnified,
			expected: int(INFRA_TYPE_UNIFIED),
			hasError: false,
		},
		{
			name:     "Broker infra type",
			infra:    InfraTypeBroker,
			expected: int(INFRA_TYPE_BROKER),
			hasError: false,
		},
		{
			name:     "CPAG infra type",
			infra:    InfraTypeCPAG,
			expected: int(INFRA_TYPE_CPAG),
			hasError: false,
		},
		{
			name:     "unknown infra type",
			infra:    InfraType("invalid"),
			expected: 0,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.infra.ToInt()

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

func TestOperatingMode_ToInt(t *testing.T) {
	tests := []struct {
		name     string
		mode     OperatingMode
		expected int
		hasError bool
	}{
		{
			name:     "Connector operating mode",
			mode:     OperatingModeConnector,
			expected: int(OPERATING_MODE_CONNECTOR),
			hasError: false,
		},
		{
			name:     "PEB operating mode",
			mode:     OperatingModePEB,
			expected: int(OPERATING_MODE_PEB),
			hasError: false,
		},
		{
			name:     "Combined operating mode",
			mode:     OperatingModeCombined,
			expected: int(OPERATING_MODE_COMBINED),
			hasError: false,
		},
		{
			name:     "CPAG Public operating mode",
			mode:     OperatingModeCPAGPublic,
			expected: int(OPERATING_MODE_CPAG_PUBLIC),
			hasError: false,
		},
		{
			name:     "CPAG Private operating mode",
			mode:     OperatingModeCPAGPrivate,
			expected: int(OPERATING_MODE_CPAG_PRIVATE),
			hasError: false,
		},
		{
			name:     "Connector with China Acceleration operating mode",
			mode:     OperatingModeConnectorWithChinaAccel,
			expected: int(OPERATING_MODE_CONNECTOR_WITH_CHINA_ACCELERATION),
			hasError: false,
		},
		{
			name:     "unknown operating mode",
			mode:     OperatingMode("invalid"),
			expected: 0,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.mode.ToInt()

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

func TestConnPackageType_ToInt(t *testing.T) {
	tests := []struct {
		name        string
		packageType ConnPackageType
		expected    int
		hasError    bool
	}{
		{
			name:        "VMware package type",
			packageType: ConnPackageTypeVmware,
			expected:    int(AGENT_PACKAGE_VMWARE),
			hasError:    false,
		},
		{
			name:        "VBox package type",
			packageType: ConnPackageTypeVbox,
			expected:    int(AGENT_PACKAGE_VBOX),
			hasError:    false,
		},
		{
			name:        "AWS package type",
			packageType: ConnPackageTypeAWS,
			expected:    int(AGENT_PACKAGE_AWS),
			hasError:    false,
		},
		{
			name:        "KVM package type",
			packageType: ConnPackageTypeKVM,
			expected:    int(AGENT_PACKAGE_KVM),
			hasError:    false,
		},
		{
			name:        "HyperV package type",
			packageType: ConnPackageTypeHyperv,
			expected:    int(AGENT_PACKAGE_HYPERV),
			hasError:    false,
		},
		{
			name:        "Docker package type",
			packageType: ConnPackageTypeDocker,
			expected:    int(AGENT_PACKAGE_DOCKER),
			hasError:    false,
		},
		{
			name:        "AWS Classic package type",
			packageType: ConnPackageTypeAWSClassic,
			expected:    int(AGENT_PACKAGE_AWS_CLASSIC),
			hasError:    false,
		},
		{
			name:        "Azure package type",
			packageType: ConnPackageTypeAzure,
			expected:    int(AGENT_PACKAGE_AZURE),
			hasError:    false,
		},
		{
			name:        "Google package type",
			packageType: ConnPackageTypeGoogle,
			expected:    int(AGENT_PACKAGE_GOOGLE),
			hasError:    false,
		},
		{
			name:        "SoftLayer package type",
			packageType: ConnPackageTypeSoftLayer,
			expected:    int(AGENT_PACKAGE_SOFTLAYER),
			hasError:    false,
		},
		{
			name:        "Fujitsu K5 package type",
			packageType: ConnPackageTypeFujitsu_k5,
			expected:    int(AGENT_PACKAGE_FUJITSU_K5),
			hasError:    false,
		},
		{
			name:        "unknown package type",
			packageType: ConnPackageType("invalid"),
			expected:    0,
			hasError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.packageType.ToInt()

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
