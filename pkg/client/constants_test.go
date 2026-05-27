package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDomain_ToInt(t *testing.T) {
	tests := map[string]struct {
		input       Domain
		expected    int
		expectError bool
	}{
		"custom": {
			input:    AppDomainCustom,
			expected: int(APP_DOMAIN_CUSTOM),
		},
		"wapp": {
			input:    AppDomainWapp,
			expected: int(APP_DOMAIN_WAPP),
		},
		"unknown": {
			input:       Domain("unknown"),
			expectError: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := tc.input.ToInt()
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestDomainInt_String(t *testing.T) {
	tests := map[string]struct {
		expected    string
		input       DomainInt
		expectError bool
	}{
		"APP_DOMAIN_CUSTOM": {
			input:    APP_DOMAIN_CUSTOM,
			expected: "custom",
		},
		"APP_DOMAIN_WAPP": {
			input:    APP_DOMAIN_WAPP,
			expected: "wapp",
		},
		"unknown": {
			input:       DomainInt(99),
			expectError: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := tc.input.String()
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestAppProfile_ToInt(t *testing.T) {
	tests := map[string]struct {
		input       AppProfile
		expected    int
		expectError bool
	}{
		"http": {
			input:    AppProfileHTTP,
			expected: int(APP_PROFILE_HTTP),
		},
		"sharepoint": {
			input:    AppProfileSharePoint,
			expected: int(APP_PROFILE_SHAREPOINT),
		},
		"jira": {
			input:    AppProfileJira,
			expected: int(APP_PROFILE_JIRA),
		},
		"rdp": {
			input:    AppProfileRDP,
			expected: int(APP_PROFILE_RDP),
		},
		"vnc": {
			input:    AppProfileVNC,
			expected: int(APP_PROFILE_VNC),
		},
		"ssh": {
			input:    AppProfileSSH,
			expected: int(APP_PROFILE_SSH),
		},
		"jenkins": {
			input:    AppProfileJenkins,
			expected: int(APP_PROFILE_JENKINS),
		},
		"confluence": {
			input:    AppProfileConfluence,
			expected: int(APP_PROFILE_CONFLUENCE),
		},
		"tcp": {
			input:    AppProfileTCP,
			expected: int(APP_PROFILE_TCP),
		},
		"smb": {
			input:    AppProfileSMB,
			expected: int(APP_PROFILE_SMB),
		},
		"unknown": {
			input:       AppProfile("unknown"),
			expectError: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := tc.input.ToInt()
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestAppProfileInt_String(t *testing.T) {
	tests := map[string]struct {
		expected    string
		input       AppProfileInt
		expectError bool
	}{
		"APP_PROFILE_HTTP": {
			input:    APP_PROFILE_HTTP,
			expected: "http",
		},
		"APP_PROFILE_SHAREPOINT": {
			input:    APP_PROFILE_SHAREPOINT,
			expected: "sharepoint",
		},
		"APP_PROFILE_JIRA": {
			input:    APP_PROFILE_JIRA,
			expected: "jira",
		},
		"APP_PROFILE_RDP": {
			input:    APP_PROFILE_RDP,
			expected: "rdp",
		},
		"APP_PROFILE_VNC": {
			input:    APP_PROFILE_VNC,
			expected: "vnc",
		},
		"APP_PROFILE_SSH": {
			input:    APP_PROFILE_SSH,
			expected: "ssh",
		},
		"APP_PROFILE_JENKINS": {
			input:    APP_PROFILE_JENKINS,
			expected: "jenkins",
		},
		"APP_PROFILE_CONFLUENCE": {
			input:    APP_PROFILE_CONFLUENCE,
			expected: "confluence",
		},
		"APP_PROFILE_TCP": {
			input:    APP_PROFILE_TCP,
			expected: "tcp",
		},
		"APP_PROFILE_SMB": {
			input:    APP_PROFILE_SMB,
			expected: "smb",
		},
		"unknown": {
			input:       AppProfileInt(99),
			expectError: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := tc.input.String()
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestAppMode_ToInt(t *testing.T) {
	tests := map[string]struct {
		input       AppMode
		expected    int
		expectError bool
	}{
		"tcp": {
			input:    ClientAppModeTCP,
			expected: int(CLIENT_APP_MODE_TCP),
		},
		"tunnel": {
			input:    ClientAppModeTunnel,
			expected: int(CLIENT_APP_MODE_TUNNEL),
		},
		"unknown": {
			input:       AppMode("unknown"),
			expectError: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := tc.input.ToInt()
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestAppModeInt_String(t *testing.T) {
	tests := map[string]struct {
		expected    string
		input       AppModeInt
		expectError bool
	}{
		"CLIENT_APP_MODE_TCP": {
			input:    CLIENT_APP_MODE_TCP,
			expected: "tcp",
		},
		"CLIENT_APP_MODE_TUNNEL": {
			input:    CLIENT_APP_MODE_TUNNEL,
			expected: "tunnel",
		},
		"unknown": {
			input:       AppModeInt(99),
			expectError: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := tc.input.String()
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestAppType_ToInt(t *testing.T) {
	tests := map[string]struct {
		input       AppType
		expected    int
		expectError bool
	}{
		"enterprise": {
			input:    ClientAppTypeEnterprise,
			expected: int(APP_TYPE_ENTERPRISE_HOSTED),
		},
		"saas": {
			input:    ClientAppTypeSaaS,
			expected: int(APP_TYPE_SAAS),
		},
		"bookmark": {
			input:    ClientAppTypeBookmark,
			expected: int(APP_TYPE_BOOKMARK),
		},
		"tunnel": {
			input:    ClientAppTypeTunnel,
			expected: int(APP_TYPE_TUNNEL),
		},
		"unknown": {
			input:       AppType("unknown"),
			expectError: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := tc.input.ToInt()
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestAppTypeInt_String(t *testing.T) {
	tests := map[string]struct {
		expected    string
		input       AppTypeInt
		expectError bool
	}{
		"APP_TYPE_ENTERPRISE_HOSTED": {
			input:    APP_TYPE_ENTERPRISE_HOSTED,
			expected: "enterprise",
		},
		"APP_TYPE_SAAS": {
			input:    APP_TYPE_SAAS,
			expected: "saas",
		},
		"APP_TYPE_BOOKMARK": {
			input:    APP_TYPE_BOOKMARK,
			expected: "bookmark",
		},
		"APP_TYPE_TUNNEL": {
			input:    APP_TYPE_TUNNEL,
			expected: "tunnel",
		},
		"unknown": {
			input:       AppTypeInt(99),
			expectError: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := tc.input.String()
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}
