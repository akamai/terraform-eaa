package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDomain_ToInt(t *testing.T) {
	testToInt(t, Domain.ToInt, map[string]toIntCase[Domain]{
		"custom":  {input: AppDomainCustom, expected: int(APP_DOMAIN_CUSTOM)},
		"wapp":    {input: AppDomainWapp, expected: int(APP_DOMAIN_WAPP)},
		"unknown": {input: Domain("unknown"), wantErr: true},
	})
}

func TestDomainInt_String(t *testing.T) {
	testToString(t, DomainInt.String, map[string]toStringCase[DomainInt]{
		"APP_DOMAIN_CUSTOM": {input: APP_DOMAIN_CUSTOM, expected: "custom"},
		"APP_DOMAIN_WAPP":   {input: APP_DOMAIN_WAPP, expected: "wapp"},
		"unknown":           {input: DomainInt(99), wantErr: true},
	})
}

func TestAppProfile_ToInt(t *testing.T) {
	testToInt(t, AppProfile.ToInt, map[string]toIntCase[AppProfile]{
		"http":       {input: AppProfileHTTP, expected: int(APP_PROFILE_HTTP)},
		"sharepoint": {input: AppProfileSharePoint, expected: int(APP_PROFILE_SHAREPOINT)},
		"jira":       {input: AppProfileJira, expected: int(APP_PROFILE_JIRA)},
		"rdp":        {input: AppProfileRDP, expected: int(APP_PROFILE_RDP)},
		"vnc":        {input: AppProfileVNC, expected: int(APP_PROFILE_VNC)},
		"ssh":        {input: AppProfileSSH, expected: int(APP_PROFILE_SSH)},
		"jenkins":    {input: AppProfileJenkins, expected: int(APP_PROFILE_JENKINS)},
		"confluence": {input: AppProfileConfluence, expected: int(APP_PROFILE_CONFLUENCE)},
		"tcp":        {input: AppProfileTCP, expected: int(APP_PROFILE_TCP)},
		"smb":        {input: AppProfileSMB, expected: int(APP_PROFILE_SMB)},
		"unknown":    {input: AppProfile("unknown"), wantErr: true},
	})
}

func TestAppProfileInt_String(t *testing.T) {
	testToString(t, AppProfileInt.String, map[string]toStringCase[AppProfileInt]{
		"APP_PROFILE_HTTP":       {input: APP_PROFILE_HTTP, expected: "http"},
		"APP_PROFILE_SHAREPOINT": {input: APP_PROFILE_SHAREPOINT, expected: "sharepoint"},
		"APP_PROFILE_JIRA":       {input: APP_PROFILE_JIRA, expected: "jira"},
		"APP_PROFILE_RDP":        {input: APP_PROFILE_RDP, expected: "rdp"},
		"APP_PROFILE_VNC":        {input: APP_PROFILE_VNC, expected: "vnc"},
		"APP_PROFILE_SSH":        {input: APP_PROFILE_SSH, expected: "ssh"},
		"APP_PROFILE_JENKINS":    {input: APP_PROFILE_JENKINS, expected: "jenkins"},
		"APP_PROFILE_CONFLUENCE": {input: APP_PROFILE_CONFLUENCE, expected: "confluence"},
		"APP_PROFILE_TCP":        {input: APP_PROFILE_TCP, expected: "tcp"},
		"APP_PROFILE_SMB":        {input: APP_PROFILE_SMB, expected: "smb"},
		"unknown":                {input: AppProfileInt(99), wantErr: true},
	})
}

func TestAppMode_ToInt(t *testing.T) {
	testToInt(t, AppMode.ToInt, map[string]toIntCase[AppMode]{
		"tcp":     {input: ClientAppModeTCP, expected: int(CLIENT_APP_MODE_TCP)},
		"tunnel":  {input: ClientAppModeTunnel, expected: int(CLIENT_APP_MODE_TUNNEL)},
		"unknown": {input: AppMode("unknown"), wantErr: true},
	})
}

func TestAppModeInt_String(t *testing.T) {
	testToString(t, AppModeInt.String, map[string]toStringCase[AppModeInt]{
		"CLIENT_APP_MODE_TCP":    {input: CLIENT_APP_MODE_TCP, expected: "tcp"},
		"CLIENT_APP_MODE_TUNNEL": {input: CLIENT_APP_MODE_TUNNEL, expected: "tunnel"},
		"unknown":                {input: AppModeInt(99), wantErr: true},
	})
}

func TestAppType_ToInt(t *testing.T) {
	testToInt(t, AppType.ToInt, map[string]toIntCase[AppType]{
		"enterprise": {input: ClientAppTypeEnterprise, expected: int(APP_TYPE_ENTERPRISE_HOSTED)},
		"saas":       {input: ClientAppTypeSaaS, expected: int(APP_TYPE_SAAS)},
		"bookmark":   {input: ClientAppTypeBookmark, expected: int(APP_TYPE_BOOKMARK)},
		"tunnel":     {input: ClientAppTypeTunnel, expected: int(APP_TYPE_TUNNEL)},
		"unknown":    {input: AppType("unknown"), wantErr: true},
	})
}

func TestAppTypeInt_String(t *testing.T) {
	testToString(t, AppTypeInt.String, map[string]toStringCase[AppTypeInt]{
		"APP_TYPE_ENTERPRISE_HOSTED": {input: APP_TYPE_ENTERPRISE_HOSTED, expected: "enterprise"},
		"APP_TYPE_SAAS":              {input: APP_TYPE_SAAS, expected: "saas"},
		"APP_TYPE_BOOKMARK":          {input: APP_TYPE_BOOKMARK, expected: "bookmark"},
		"APP_TYPE_TUNNEL":            {input: APP_TYPE_TUNNEL, expected: "tunnel"},
		"unknown":                    {input: AppTypeInt(99), wantErr: true},
	})
}

func TestConnPackageType_ToInt(t *testing.T) {
	testToInt(t, ConnPackageType.ToInt, map[string]toIntCase[ConnPackageType]{
		"vmware":      {input: ConnPackageTypeVmware, expected: int(AGENT_PACKAGE_VMWARE)},
		"vbox":        {input: ConnPackageTypeVbox, expected: int(AGENT_PACKAGE_VBOX)},
		"aws":         {input: ConnPackageTypeAWS, expected: int(AGENT_PACKAGE_AWS)},
		"kvm":         {input: ConnPackageTypeKVM, expected: int(AGENT_PACKAGE_KVM)},
		"hyperv":      {input: ConnPackageTypeHyperv, expected: int(AGENT_PACKAGE_HYPERV)},
		"docker":      {input: ConnPackageTypeDocker, expected: int(AGENT_PACKAGE_DOCKER)},
		"aws_classic": {input: ConnPackageTypeAWSClassic, expected: int(AGENT_PACKAGE_AWS_CLASSIC)},
		"azure":       {input: ConnPackageTypeAzure, expected: int(AGENT_PACKAGE_AZURE)},
		"google":      {input: ConnPackageTypeGoogle, expected: int(AGENT_PACKAGE_GOOGLE)},
		"softlayer":   {input: ConnPackageTypeSoftLayer, expected: int(AGENT_PACKAGE_SOFTLAYER)},
		"fujitsu_k5":  {input: ConnPackageTypeFujitsu_k5, expected: int(AGENT_PACKAGE_FUJITSU_K5)},
		"unknown":     {input: ConnPackageType("unknown"), wantErr: true},
	})
}

func TestConnPackageTypeInt_String(t *testing.T) {
	testToString(t, ConnPackageTypeInt.String, map[string]toStringCase[ConnPackageTypeInt]{
		"AGENT_PACKAGE_VMWARE":      {input: AGENT_PACKAGE_VMWARE, expected: "vmware"},
		"AGENT_PACKAGE_VBOX":        {input: AGENT_PACKAGE_VBOX, expected: "vbox"},
		"AGENT_PACKAGE_AWS":         {input: AGENT_PACKAGE_AWS, expected: "aws"},
		"AGENT_PACKAGE_KVM":         {input: AGENT_PACKAGE_KVM, expected: "kvm"},
		"AGENT_PACKAGE_HYPERV":      {input: AGENT_PACKAGE_HYPERV, expected: "hyperv"},
		"AGENT_PACKAGE_DOCKER":      {input: AGENT_PACKAGE_DOCKER, expected: "docker"},
		"AGENT_PACKAGE_AWS_CLASSIC": {input: AGENT_PACKAGE_AWS_CLASSIC, expected: "aws_classic"},
		"AGENT_PACKAGE_AZURE":       {input: AGENT_PACKAGE_AZURE, expected: "azure"},
		"AGENT_PACKAGE_GOOGLE":      {input: AGENT_PACKAGE_GOOGLE, expected: "google"},
		"AGENT_PACKAGE_SOFTLAYER":   {input: AGENT_PACKAGE_SOFTLAYER, expected: "softlayer"},
		"AGENT_PACKAGE_FUJITSU_K5":  {input: AGENT_PACKAGE_FUJITSU_K5, expected: "fujitsu_k5"},
		"unknown":                   {input: ConnPackageTypeInt(99), wantErr: true},
	})
}

func TestConnPackageStateInt_String(t *testing.T) {
	testToString(t, ConnPackageStateInt.String, map[string]toStringCase[ConnPackageStateInt]{
		"AGENT_STATE_NOT_CREATED":    {input: AGENT_STATE_NOT_CREATED, expected: "not_created"},
		"AGENT_STATE_CREATED":        {input: AGENT_STATE_CREATED, expected: "created"},
		"AGENT_STATE_NOT_INSTALLED":  {input: AGENT_STATE_NOT_INSTALLED, expected: "not_installed"},
		"AGENT_STATE_NOT_VERIFIED":   {input: AGENT_STATE_NOT_VERIFIED, expected: "not_verified"},
		"AGENT_STATE_VERIFIED":       {input: AGENT_STATE_VERIFIED, expected: "verified"},
		"AGENT_STATE_UNENROLLED":     {input: AGENT_STATE_UNENROLLED, expected: "unenrolled"},
		"AGENT_STATE_ENROLLED":       {input: AGENT_STATE_ENROLLED, expected: "enrolled"},
		"AGENT_STATE_NOT_CONFIGURED": {input: AGENT_STATE_NOT_CONFIGURED, expected: "not_configured"},
		"AGENT_STATE_CONFIGURED":     {input: AGENT_STATE_CONFIGURED, expected: "configured"},
		"unknown":                    {input: ConnPackageStateInt(99), wantErr: true},
	})
}

func TestServiceType_ToInt(t *testing.T) {
	testToInt(t, ServiceType.ToInt, map[string]toIntCase[ServiceType]{
		"waf":          {input: ServiceTypeWAF, expected: int(SERVICE_TYPE_WAF)},
		"acceleration": {input: ServiceTypeAcceleration, expected: int(SERVICE_TYPE_ACCELERATION)},
		"av":           {input: ServiceTypeAV, expected: int(SERVICE_TYPE_AV)},
		"ips":          {input: ServiceTypeIPS, expected: int(SERVICE_TYPE_IPS)},
		"slb":          {input: ServiceTypeSLB, expected: int(SERVICE_TYPE_SLB)},
		"access":       {input: ServiceTypeAccessCtrl, expected: int(SERVICE_TYPE_ACCESS_CTRL)},
		"rewrite":      {input: ServiceTypeRewrite, expected: int(SERVICE_TYPE_REWRITE)},
		"unknown":      {input: ServiceType("unknown"), wantErr: true},
	})
}

func TestHealthCheckType_ToNumeric(t *testing.T) {
	tests := map[string]struct {
		input    HealthCheckType
		expected string
		wantErr  bool
	}{
		"default": {input: HealthCheckTypeDefault, expected: "0"},
		"http":    {input: HealthCheckTypeHTTP, expected: "1"},
		"https":   {input: HealthCheckTypeHTTPS, expected: "2"},
		"tls":     {input: HealthCheckTypeTLS, expected: "3"},
		"sslv3":   {input: HealthCheckTypeSSLv3, expected: "4"},
		"tcp":     {input: HealthCheckTypeTCP, expected: "5"},
		"none":    {input: HealthCheckTypeNone, expected: "6"},
		"unknown": {input: HealthCheckType("99"), wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := tc.input.ToNumeric()
			if requireErr(t, err, tc.wantErr) {
				return
			}
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestHealthCheckTypeInt_ToDescriptive(t *testing.T) {
	testToString(t, HealthCheckTypeInt.ToDescriptive, map[string]toStringCase[HealthCheckTypeInt]{
		"HEALTH_CHECK_TYPE_DEFAULT": {input: HEALTH_CHECK_TYPE_DEFAULT, expected: "Default"},
		"HEALTH_CHECK_TYPE_HTTP":    {input: HEALTH_CHECK_TYPE_HTTP, expected: "HTTP"},
		"HEALTH_CHECK_TYPE_HTTPS":   {input: HEALTH_CHECK_TYPE_HTTPS, expected: "HTTPS"},
		"HEALTH_CHECK_TYPE_TLS":     {input: HEALTH_CHECK_TYPE_TLS, expected: "TLS"},
		"HEALTH_CHECK_TYPE_SSLV3":   {input: HEALTH_CHECK_TYPE_SSLV3, expected: "SSLv3"},
		"HEALTH_CHECK_TYPE_TCP":     {input: HEALTH_CHECK_TYPE_TCP, expected: "TCP"},
		"HEALTH_CHECK_TYPE_NONE":    {input: HEALTH_CHECK_TYPE_NONE, expected: "None"},
		"unknown":                   {input: HealthCheckTypeInt(99), wantErr: true},
	})
}

func TestMapHealthCheckTypeToDescriptive(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected string
		errIsNil bool
	}{
		"0":       {input: "0", expected: "Default", errIsNil: true},
		"1":       {input: "1", expected: "HTTP", errIsNil: true},
		"2":       {input: "2", expected: "HTTPS", errIsNil: true},
		"3":       {input: "3", expected: "TLS", errIsNil: true},
		"4":       {input: "4", expected: "SSLv3", errIsNil: true},
		"5":       {input: "5", expected: "TCP", errIsNil: true},
		"6":       {input: "6", expected: "None", errIsNil: true},
		"empty":   {input: "", expected: "", errIsNil: true},
		"unknown": {input: "unknown", errIsNil: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := MapHealthCheckTypeToDescriptive(tc.input)
			if tc.errIsNil {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
				return
			}
			require.Error(t, err)
		})
	}
}

func TestMapHealthCheckTypeToNumeric(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected string
		errIsNil bool
	}{
		"Default":       {input: "Default", expected: "0", errIsNil: true},
		"HTTP":          {input: "HTTP", expected: "1", errIsNil: true},
		"HTTPS":         {input: "HTTPS", expected: "2", errIsNil: true},
		"TLS":           {input: "TLS", expected: "3", errIsNil: true},
		"SSLv3":         {input: "SSLv3", expected: "4", errIsNil: true},
		"TCP":           {input: "TCP", expected: "5", errIsNil: true},
		"None":          {input: "None", expected: "6", errIsNil: true},
		"known_numeric": {input: "6", expected: "6", errIsNil: true},
		"empty":         {input: "", expected: "", errIsNil: true},
		"unknown":       {input: "99", errIsNil: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := MapHealthCheckTypeToNumeric(tc.input)
			if tc.errIsNil {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
				return
			}
			require.Error(t, err)
		})
	}
}

func TestInfraType_ToInt(t *testing.T) {
	testToInt(t, InfraType.ToInt, map[string]toIntCase[InfraType]{
		"eaa":     {input: InfraTypeEAA, expected: int(INFRA_TYPE_EAA)},
		"unified": {input: InfraTypeUnified, expected: int(INFRA_TYPE_UNIFIED)},
		"broker":  {input: InfraTypeBroker, expected: int(INFRA_TYPE_BROKER)},
		"cpag":    {input: InfraTypeCPAG, expected: int(INFRA_TYPE_CPAG)},
		"unknown": {input: InfraType("unknown"), wantErr: true},
	})
}

func TestInfraTypeInt_String(t *testing.T) {
	testToString(t, InfraTypeInt.String, map[string]toStringCase[InfraTypeInt]{
		"INFRA_TYPE_EAA":     {input: INFRA_TYPE_EAA, expected: "eaa"},
		"INFRA_TYPE_UNIFIED": {input: INFRA_TYPE_UNIFIED, expected: "unified"},
		"INFRA_TYPE_BROKER":  {input: INFRA_TYPE_BROKER, expected: "broker"},
		"INFRA_TYPE_CPAG":    {input: INFRA_TYPE_CPAG, expected: "cpag"},
		"unknown":            {input: InfraTypeInt(99), wantErr: true},
	})
}

func TestOperatingMode_ToInt(t *testing.T) {
	testToInt(t, OperatingMode.ToInt, map[string]toIntCase[OperatingMode]{
		"connector":                         {input: OperatingModeConnector, expected: int(OPERATING_MODE_CONNECTOR)},
		"peb":                               {input: OperatingModePEB, expected: int(OPERATING_MODE_PEB)},
		"combined":                          {input: OperatingModeCombined, expected: int(OPERATING_MODE_COMBINED)},
		"cpag_public":                       {input: OperatingModeCPAGPublic, expected: int(OPERATING_MODE_CPAG_PUBLIC)},
		"cpag_private":                      {input: OperatingModeCPAGPrivate, expected: int(OPERATING_MODE_CPAG_PRIVATE)},
		"connector_with_china_acceleration": {input: OperatingModeConnectorWithChinaAccel, expected: int(OPERATING_MODE_CONNECTOR_WITH_CHINA_ACCELERATION)},
		"unknown":                           {input: OperatingMode("unknown"), wantErr: true},
	})
}

func TestOperatingModeInt_String(t *testing.T) {
	testToString(t, OperatingModeInt.String, map[string]toStringCase[OperatingModeInt]{
		"OPERATING_MODE_CONNECTOR":                         {input: OPERATING_MODE_CONNECTOR, expected: "connector"},
		"OPERATING_MODE_PEB":                               {input: OPERATING_MODE_PEB, expected: "peb"},
		"OPERATING_MODE_COMBINED":                          {input: OPERATING_MODE_COMBINED, expected: "combined"},
		"OPERATING_MODE_CPAG_PUBLIC":                       {input: OPERATING_MODE_CPAG_PUBLIC, expected: "cpag_public"},
		"OPERATING_MODE_CPAG_PRIVATE":                      {input: OPERATING_MODE_CPAG_PRIVATE, expected: "cpag_private"},
		"OPERATING_MODE_CONNECTOR_WITH_CHINA_ACCELERATION": {input: OPERATING_MODE_CONNECTOR_WITH_CHINA_ACCELERATION, expected: "connector_with_china_acceleration"},
		"unknown": {input: OperatingModeInt(99), wantErr: true},
	})
}
