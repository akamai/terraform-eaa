package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientAppType_ToInt(t *testing.T) {
	tests := []struct {
		name    string
		appType ClientAppType
		want    int
		wantErr bool
	}{
		{
			name:    "enterprise app type",
			appType: ClientAppTypeEnterprise,
			want:    int(APP_TYPE_ENTERPRISE_HOSTED),
			wantErr: false,
		},
		{
			name:    "saas app type",
			appType: ClientAppTypeSaaS,
			want:    int(APP_TYPE_SAAS),
			wantErr: false,
		},
		{
			name:    "bookmark app type",
			appType: ClientAppTypeBookmark,
			want:    int(APP_TYPE_BOOKMARK),
			wantErr: false,
		},
		{
			name:    "tunnel app type",
			appType: ClientAppTypeTunnel,
			want:    int(APP_TYPE_TUNNEL),
			wantErr: false,
		},
		{
			name:    "unknown app type",
			appType: ClientAppType("unknown"),
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.appType.ToInt()
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, 0, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, result)
			}
		})
	}
}

func TestClientAppTypeInt_String(t *testing.T) {
	tests := []struct {
		name       string
		appTypeInt ClientAppTypeInt
		want       string
		wantErr    bool
	}{
		{
			name:       "enterprise app type int",
			appTypeInt: APP_TYPE_ENTERPRISE_HOSTED,
			want:       string(ClientAppTypeEnterprise),
			wantErr:    false,
		},
		{
			name:       "saas app type int",
			appTypeInt: APP_TYPE_SAAS,
			want:       string(ClientAppTypeSaaS),
			wantErr:    false,
		},
		{
			name:       "bookmark app type int",
			appTypeInt: APP_TYPE_BOOKMARK,
			want:       string(ClientAppTypeBookmark),
			wantErr:    false,
		},
		{
			name:       "tunnel app type int",
			appTypeInt: APP_TYPE_TUNNEL,
			want:       string(ClientAppTypeTunnel),
			wantErr:    false,
		},
		{
			name:       "unknown app type int",
			appTypeInt: ClientAppTypeInt(999),
			want:       "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.appTypeInt.String()
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, "", result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, result)
			}
		})
	}
}

// Test DomainInt.String() function
func TestDomainInt_String(t *testing.T) {
	testCases := []struct {
		name     string
		domain   DomainInt
		expected string
		hasError bool
	}{
		{
			name:     "custom domain",
			domain:   APP_DOMAIN_CUSTOM,
			expected: string(AppDomainCustom),
			hasError: false,
		},
		{
			name:     "wapp domain",
			domain:   APP_DOMAIN_WAPP,
			expected: string(AppDomainWapp),
			hasError: false,
		},
		{
			name:     "unknown domain",
			domain:   DomainInt(999),
			expected: "",
			hasError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.domain.String()

			if tc.hasError {
				assert.Error(t, err)
				assert.Equal(t, tc.expected, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

// Test AppProfileInt.String() function
func TestAppProfileInt_String(t *testing.T) {
	testCases := []struct {
		name     string
		profile  AppProfileInt
		expected string
		hasError bool
	}{
		{
			name:     "HTTP profile",
			profile:  APP_PROFILE_HTTP,
			expected: string(AppProfileHTTP),
			hasError: false,
		},
		{
			name:     "SharePoint profile",
			profile:  APP_PROFILE_SHAREPOINT,
			expected: string(AppProfileSharePoint),
			hasError: false,
		},
		{
			name:     "RDP profile",
			profile:  APP_PROFILE_RDP,
			expected: string(AppProfileRDP),
			hasError: false,
		},
		{
			name:     "SSH profile",
			profile:  APP_PROFILE_SSH,
			expected: string(AppProfileSSH),
			hasError: false,
		},
		{
			name:     "Jira profile",
			profile:  APP_PROFILE_JIRA,
			expected: string(AppProfileJira),
			hasError: false,
		},
		{
			name:     "VNC profile",
			profile:  APP_PROFILE_VNC,
			expected: string(AppProfileVNC),
			hasError: false,
		},
		{
			name:     "Jenkins profile",
			profile:  APP_PROFILE_JENKINS,
			expected: string(AppProfileJenkins),
			hasError: false,
		},
		{
			name:     "Confluence profile",
			profile:  APP_PROFILE_CONFLUENCE,
			expected: string(AppProfileConfluence),
			hasError: false,
		},
		{
			name:     "TCP profile",
			profile:  APP_PROFILE_TCP,
			expected: string(AppProfileTCP),
			hasError: false,
		},
		{
			name:     "SMB profile",
			profile:  APP_PROFILE_SMB,
			expected: string(AppProfileSMB),
			hasError: false,
		},
		{
			name:     "unknown profile",
			profile:  AppProfileInt(999),
			expected: "",
			hasError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.profile.String()

			if tc.hasError {
				assert.Error(t, err)
				assert.Equal(t, tc.expected, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

// Test ClientAppModeInt.String() function
func TestClientAppModeInt_String(t *testing.T) {
	testCases := []struct {
		name     string
		mode     ClientAppModeInt
		expected string
		hasError bool
	}{
		{
			name:     "TCP mode",
			mode:     CLIENT_APP_MODE_TCP,
			expected: string(ClientAppModeTCP),
			hasError: false,
		},
		{
			name:     "Tunnel mode",
			mode:     CLIENT_APP_MODE_TUNNEL,
			expected: string(ClientAppModeTunnel),
			hasError: false,
		},
		{
			name:     "unknown mode",
			mode:     ClientAppModeInt(999),
			expected: "",
			hasError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.mode.String()

			if tc.hasError {
				assert.Error(t, err)
				assert.Equal(t, tc.expected, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

// Test ConnPackageTypeInt.String() function
func TestConnPackageTypeInt_String(t *testing.T) {
	testCases := []struct {
		name     string
		pkgType  ConnPackageTypeInt
		expected string
		hasError bool
	}{
		{
			name:     "VMware package",
			pkgType:  AGENT_PACKAGE_VMWARE,
			expected: string(ConnPackageTypeVmware),
			hasError: false,
		},
		{
			name:     "AWS package",
			pkgType:  AGENT_PACKAGE_AWS,
			expected: string(ConnPackageTypeAWS),
			hasError: false,
		},
		{
			name:     "Docker package",
			pkgType:  AGENT_PACKAGE_DOCKER,
			expected: string(ConnPackageTypeDocker),
			hasError: false,
		},
		{
			name:     "Azure package",
			pkgType:  AGENT_PACKAGE_AZURE,
			expected: string(ConnPackageTypeAzure),
			hasError: false,
		},
		{
			name:     "VBox package",
			pkgType:  AGENT_PACKAGE_VBOX,
			expected: string(ConnPackageTypeVbox),
			hasError: false,
		},
		{
			name:     "KVM package",
			pkgType:  AGENT_PACKAGE_KVM,
			expected: string(ConnPackageTypeKVM),
			hasError: false,
		},
		{
			name:     "HyperV package",
			pkgType:  AGENT_PACKAGE_HYPERV,
			expected: string(ConnPackageTypeHyperv),
			hasError: false,
		},
		{
			name:     "AWS Classic package",
			pkgType:  AGENT_PACKAGE_AWS_CLASSIC,
			expected: string(ConnPackageTypeAWSClassic),
			hasError: false,
		},
		{
			name:     "Google package",
			pkgType:  AGENT_PACKAGE_GOOGLE,
			expected: string(ConnPackageTypeGoogle),
			hasError: false,
		},
		{
			name:     "SoftLayer package",
			pkgType:  AGENT_PACKAGE_SOFTLAYER,
			expected: string(ConnPackageTypeSoftLayer),
			hasError: false,
		},
		{
			name:     "Fujitsu K5 package",
			pkgType:  AGENT_PACKAGE_FUJITSU_K5,
			expected: string(ConnPackageTypeFujitsu_k5),
			hasError: false,
		},
		{
			name:     "unknown package type",
			pkgType:  ConnPackageTypeInt(999),
			expected: "",
			hasError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.pkgType.String()

			if tc.hasError {
				assert.Error(t, err)
				assert.Equal(t, tc.expected, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

// Test ConnPackageStateInt.String() function
func TestConnPackageStateInt_String(t *testing.T) {
	testCases := []struct {
		name     string
		state    ConnPackageStateInt
		expected string
		hasError bool
	}{
		{
			name:     "not created state",
			state:    AGENT_STATE_NOT_CREATED,
			expected: string(ConnPackageStateNotCreated),
			hasError: false,
		},
		{
			name:     "created state",
			state:    AGENT_STATE_CREATED,
			expected: string(ConnPackageStateCreated),
			hasError: false,
		},
		{
			name:     "verified state",
			state:    AGENT_STATE_VERIFIED,
			expected: string(ConnPackageStateVerified),
			hasError: false,
		},
		{
			name:     "configured state",
			state:    AGENT_STATE_CONFIGURED,
			expected: string(ConnPackageStateConfigured),
			hasError: false,
		},
		{
			name:     "not configured state",
			state:    AGENT_STATE_NOT_CONFIGURED,
			expected: string(ConnPackageStateNotConfigured),
			hasError: false,
		},
		{
			name:     "not installed state",
			state:    AGENT_STATE_NOT_INSTALLED,
			expected: string(ConnPackageStateNotInstalled),
			hasError: false,
		},
		{
			name:     "not verified state",
			state:    AGENT_STATE_NOT_VERIFIED,
			expected: string(ConnPackageStateNotVerified),
			hasError: false,
		},
		{
			name:     "unenrolled state",
			state:    AGENT_STATE_UNENROLLED,
			expected: string(ConnPackageStateUnenrolled),
			hasError: false,
		},
		{
			name:     "enrolled state - not supported by String() method",
			state:    AGENT_STATE_ENROLLED,
			expected: "",
			hasError: true, // AGENT_STATE_ENROLLED is not handled in ConnPackageStateInt.String()
		},
		{
			name:     "unknown state",
			state:    ConnPackageStateInt(999),
			expected: "",
			hasError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.state.String()

			if tc.hasError {
				assert.Error(t, err)
				assert.Equal(t, tc.expected, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

// Test InfraTypeInt.String() function
func TestInfraTypeInt_String(t *testing.T) {
	testCases := []struct {
		name      string
		infraType InfraTypeInt
		expected  string
		hasError  bool
	}{
		{
			name:      "EAA infra type",
			infraType: INFRA_TYPE_EAA,
			expected:  string(InfraTypeEAA),
			hasError:  false,
		},
		{
			name:      "Unified infra type",
			infraType: INFRA_TYPE_UNIFIED,
			expected:  string(InfraTypeUnified),
			hasError:  false,
		},
		{
			name:      "Broker infra type",
			infraType: INFRA_TYPE_BROKER,
			expected:  string(InfraTypeBroker),
			hasError:  false,
		},
		{
			name:      "CPAG infra type",
			infraType: INFRA_TYPE_CPAG,
			expected:  string(InfraTypeCPAG),
			hasError:  false,
		},
		{
			name:      "unknown infra type",
			infraType: InfraTypeInt(999),
			expected:  "",
			hasError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.infraType.String()

			if tc.hasError {
				assert.Error(t, err)
				assert.Equal(t, tc.expected, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

// Test OperatingModeInt.String() function
func TestOperatingModeInt_String(t *testing.T) {
	testCases := []struct {
		name     string
		opMode   OperatingModeInt
		expected string
		hasError bool
	}{
		{
			name:     "Connector operating mode",
			opMode:   OPERATING_MODE_CONNECTOR,
			expected: string(OperatingModeConnector),
			hasError: false,
		},
		{
			name:     "PEB operating mode",
			opMode:   OPERATING_MODE_PEB,
			expected: string(OperatingModePEB),
			hasError: false,
		},
		{
			name:     "Combined operating mode",
			opMode:   OPERATING_MODE_COMBINED,
			expected: string(OperatingModeCombined),
			hasError: false,
		},
		{
			name:     "CPAG Public operating mode",
			opMode:   OPERATING_MODE_CPAG_PUBLIC,
			expected: string(OperatingModeCPAGPublic),
			hasError: false,
		},
		{
			name:     "CPAG Private operating mode",
			opMode:   OPERATING_MODE_CPAG_PRIVATE,
			expected: string(OperatingModeCPAGPrivate),
			hasError: false,
		},
		{
			name:     "Connector with China Acceleration",
			opMode:   OPERATING_MODE_CONNECTOR_WITH_CHINA_ACCELERATION,
			expected: string(OperatingModeConnectorWithChinaAccel),
			hasError: false,
		},
		{
			name:     "unknown operating mode",
			opMode:   OperatingModeInt(999),
			expected: "",
			hasError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.opMode.String()

			if tc.hasError {
				assert.Error(t, err)
				assert.Equal(t, tc.expected, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}
