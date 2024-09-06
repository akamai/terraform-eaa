package client

import (
	"errors"
)

const (
	STR_TRUE      = "true"
	STR_FALSE     = "false"
	STATE_ENABLED = 1
)

const (
	MGMT_POP_URL       = "crux/v1/mgmt-pop"
	APPS_URL           = "crux/v1/mgmt-pop/apps"
	POPS_URL           = "crux/v1/mgmt-pop/pops"
	APPIDP_URL         = "crux/v1/mgmt-pop/appidp"
	APPDIRECTORIES_URL = "crux/v1/mgmt-pop/appdirectories"
	APPGROUPS_URL      = "crux/v1/mgmt-pop/appgroups"
	AGENTS_URL         = "crux/v1/mgmt-pop/agents"
	APP_CATEGORIES_URL = "crux/v1/mgmt-pop/appcategories"
	IDP_URL            = "crux/v1/mgmt-pop/idp"
	CERTIFICATES_URL   = "crux/v1/mgmt-pop/certificates"
	SERVICES_URL       = "crux/v1/mgmt-pop/services"
	URL_SCHEME         = "https"
)

var (
	ErrInvalidArgument = errors.New("invalid arguments provided")
	ErrMarshaling      = errors.New("marshaling input")
	ErrUnmarshaling    = errors.New("unmarshaling output")

	ErrAppCreate = errors.New("app creation failed")
	ErrAppUpdate = errors.New("app update failed")
	ErrAppDelete = errors.New("app delete failed")

	ErrAssignAgentsFailure    = errors.New("assigning agents to the app failed")
	ErrAssignIdpFailure       = errors.New("assigning IDP to the app failed")
	ErrAssignDirectoryFailure = errors.New("assigning directory to the app failed")
	ErrDeploy                 = errors.New("app deploy failed")
	ErrAssignGroupFailure     = errors.New("assigning groups to the app failed")
	ErrGetApp                 = errors.New("app deploy failed")

	ErrInvalidType  = errors.New("value must be of the specified type")
	ErrInvalidValue = errors.New("invalid value for a key")
)

type Domain string

const (
	AppDomainCustom Domain = "custom"
	AppDomainWapp   Domain = "wapp"
)

func (d Domain) ToInt() (int, error) {
	switch d {
	case AppDomainCustom:
		return int(APP_DOMAIN_CUSTOM), nil
	case AppDomainWapp:
		return int(APP_DOMAIN_WAPP), nil
	default:
		return 0, errors.New("Unknown domain value")
	}
}

type DomainInt int

const (
	APP_DOMAIN_CUSTOM DomainInt = 1 + iota
	APP_DOMAIN_WAPP
)

func (cam DomainInt) String() (string, error) {
	switch cam {
	case APP_DOMAIN_CUSTOM:
		return string(AppDomainCustom), nil
	case APP_DOMAIN_WAPP:
		return string(AppDomainWapp), nil
	default:
		return "", errors.New("Unknown domain value")
	}
}

type AppProfile string

const (
	AppProfileHTTP       AppProfile = "http"
	AppProfileSharePoint AppProfile = "sharepoint"
	AppProfileJira       AppProfile = "jira"
	AppProfileRDP        AppProfile = "rdp"
	AppProfileVNC        AppProfile = "vnc"
	AppProfileSSH        AppProfile = "ssh"
	AppProfileJenkins    AppProfile = "jenkins"
	AppProfileConfluence AppProfile = "confluence"
	AppProfileTCP        AppProfile = "tcp"
)

func (ap AppProfile) ToInt() (int, error) {
	switch ap {
	case AppProfileHTTP:
		return int(APP_PROFILE_HTTP), nil
	case AppProfileSharePoint:
		return int(APP_PROFILE_SHAREPOINT), nil
	case AppProfileJira:
		return int(APP_PROFILE_JIRA), nil
	case AppProfileRDP:
		return int(APP_PROFILE_RDP), nil
	case AppProfileVNC:
		return int(APP_PROFILE_VNC), nil
	case AppProfileSSH:
		return int(APP_PROFILE_SSH), nil
	case AppProfileJenkins:
		return int(APP_PROFILE_JENKINS), nil
	case AppProfileConfluence:
		return int(APP_PROFILE_CONFLUENCE), nil
	case AppProfileTCP:
		return int(APP_PROFILE_TCP), nil
	default:
		return 0, errors.New("Unknown App_Profile value")
	}
}

type AppProfileInt int

const (
	APP_PROFILE_HTTP AppProfileInt = 1 + iota
	APP_PROFILE_SHAREPOINT
	APP_PROFILE_JIRA
	APP_PROFILE_RDP
	APP_PROFILE_VNC
	APP_PROFILE_SSH
	APP_PROFILE_JENKINS
	APP_PROFILE_CONFLUENCE
	APP_PROFILE_TCP
)

func (cam AppProfileInt) String() (string, error) {
	switch cam {
	case APP_PROFILE_HTTP:
		return string(AppProfileHTTP), nil
	case APP_PROFILE_SHAREPOINT:
		return string(AppProfileSharePoint), nil
	case APP_PROFILE_JIRA:
		return string(AppProfileJira), nil
	case APP_PROFILE_RDP:
		return string(AppProfileRDP), nil
	case APP_PROFILE_VNC:
		return string(AppProfileVNC), nil
	case APP_PROFILE_SSH:
		return string(AppProfileSSH), nil
	case APP_PROFILE_JENKINS:
		return string(AppProfileJenkins), nil
	case APP_PROFILE_CONFLUENCE:
		return string(AppProfileConfluence), nil
	case APP_PROFILE_TCP:
		return string(AppProfileTCP), nil
	default:
		return "", errors.New("Unknown app_profile value")
	}
}

type ClientAppMode string

const (
	ClientAppModeTCP    ClientAppMode = "tcp"
	ClientAppModeTunnel ClientAppMode = "tunnel"
)

func (cam ClientAppMode) ToInt() (int, error) {
	switch cam {
	case ClientAppModeTCP:
		return int(CLIENT_APP_MODE_TCP), nil
	case ClientAppModeTunnel:
		return int(CLIENT_APP_MODE_TUNNEL), nil
	default:
		return 0, errors.New("Unknown ClientAppMode value")
	}
}

type ClientAppModeInt int

const (
	CLIENT_APP_MODE_TCP ClientAppModeInt = 1 + iota
	CLIENT_APP_MODE_TUNNEL
)

func (cam ClientAppModeInt) String() (string, error) {
	switch cam {
	case CLIENT_APP_MODE_TCP:
		return string(ClientAppModeTCP), nil
	case CLIENT_APP_MODE_TUNNEL:
		return string(ClientAppModeTunnel), nil
	default:
		return "", errors.New("Unknown ClientAppMode value")
	}
}

type ClientAppType string

const (
	ClientAppTypeEnterprise ClientAppType = "enterprise"
	ClientAppTypeSaaS       ClientAppType = "saas"
	ClientAppTypeBookmark   ClientAppType = "bookmark"
	ClientAppTypeTunnel     ClientAppType = "tunnel"
)

func (cat ClientAppType) ToInt() (int, error) {
	switch cat {
	case ClientAppTypeEnterprise:
		return int(APP_TYPE_ENTERPRISE_HOSTED), nil
	case ClientAppTypeSaaS:
		return int(APP_TYPE_SAAS), nil
	case ClientAppTypeBookmark:
		return int(APP_TYPE_BOOKMARK), nil
	case ClientAppTypeTunnel:
		return int(APP_TYPE_TUNNEL), nil
	default:
		return 0, errors.New("Unknown ClientAppType value")
	}
}

type ClientAppTypeInt int

const (
	APP_TYPE_ENTERPRISE_HOSTED ClientAppTypeInt = 1 + iota
	APP_TYPE_SAAS
	APP_TYPE_BOOKMARK
	APP_TYPE_TUNNEL
)

func (cat ClientAppTypeInt) String() (string, error) {
	switch cat {
	case APP_TYPE_ENTERPRISE_HOSTED:
		return string(ClientAppTypeEnterprise), nil
	case APP_TYPE_SAAS:
		return string(ClientAppTypeSaaS), nil
	case APP_TYPE_BOOKMARK:
		return string(ClientAppTypeBookmark), nil
	case APP_TYPE_TUNNEL:
		return string(ClientAppTypeTunnel), nil
	default:
		return "", errors.New("Unknown ClientAppType value")
	}
}

type CertType string

const (
	CertSelfSigned CertType = "self_signed"
	CertUploaded   CertType = "uploaded"
)
const (
	CERT_TYPE_APP = 1 + iota
	CERT_TYPE_AGENT
	CERT_TYPE_INTERNAL
	CERT_TYPE_USER
	CERT_TYPE_APP_SSC
	CERT_TYPE_CA
)

const (
	ACCESS_RULE_SETTING_BROWSER               = "browser"
	ACCESS_RULE_SETTING_URL                   = "url"
	ACCESS_RULE_SETTING_GROUP                 = "group"
	ACCESS_RULE_SETTING_USER                  = "user"
	ACCESS_RULE_SETTING_CLIENTIP              = "clientip"
	ACCESS_RULE_SETTING_OS                    = "os"
	ACCESS_RULE_SETTING_DEVICE                = "device"
	ACCESS_RULE_SETTING_COUNTRY               = "country"
	ACCESS_RULE_SETTING_TIME                  = "time"
	ACCESS_RULE_SETTING_METHOD                = "method"
	ACCESS_RULE_SETTING_EAACLIENT_APPHOST     = "EAAClientAppHost"
	ACCESS_RULE_SETTING_EAACLIENT_APPPORT     = "EAAClientAppPort"
	ACCESS_RULE_SETTING_EAACLIENT_APPPROTOCOL = "EAAClientAppProtocol"
	ACCESS_RULE_SETTING_DEVICE_POSTURE        = "DevicePostureRiskAssessment"
	ACCESS_RULE_SETTING_DEVICE_TIER           = "device_risk_tier"
	ACCESS_RULE_SETTING_DEVICE_TAG            = "device_risk_tag"
)

type ServiceTypeInt int

const (
	SERVICE_TYPE_WAF = 1 + iota
	SERVICE_TYPE_ACCELERATION
	SERVICE_TYPE_AV
	SERVICE_TYPE_IPS
	SERVICE_TYPE_SLB
	SERVICE_TYPE_ACCESS_CTRL
	SERVICE_TYPE_REWRITE
)

type ServiceType string

const (
	ServiceTypeWAF          ServiceType = "waf"
	ServiceTypeAcceleration ServiceType = "acceleration"
	ServiceTypeAV           ServiceType = "av"
	ServiceTypeIPS          ServiceType = "ips"
	ServiceTypeSLB          ServiceType = "slb"
	ServiceTypeAccessCtrl   ServiceType = "access"
	ServiceTypeRewrite      ServiceType = "rewrite"
)

func (s ServiceType) ToInt() (int, error) {
	switch s {
	case ServiceTypeWAF:
		return int(SERVICE_TYPE_WAF), nil
	case ServiceTypeAcceleration:
		return int(SERVICE_TYPE_ACCELERATION), nil
	case ServiceTypeAV:
		return int(SERVICE_TYPE_AV), nil
	case ServiceTypeIPS:
		return int(SERVICE_TYPE_IPS), nil
	case ServiceTypeSLB:
		return int(SERVICE_TYPE_SLB), nil
	case ServiceTypeAccessCtrl:
		return int(SERVICE_TYPE_ACCESS_CTRL), nil
	case ServiceTypeRewrite:
		return int(SERVICE_TYPE_REWRITE), nil
	default:
		return 0, errors.New("Unknown service type value")
	}
}

type RuleTypeInt int

const (
	RULE_TYPE_ACCESS_CTRL = 1 + iota
	RULE_TYPE_CONTENT_REWRITE
	RULE_TYPE_POST_REWRITE
	RULE_TYPE_QUERY_REWRITE
	RULE_TYPE_COOKIE_REWRITE
	RULE_TYPE_LOCATION_REWRITE
	RULE_TYPE_GROUP_BASED_REWRITE
)

const (
	ADMIN_STATE_ENABLED  = 1
	ADMIN_STATE_DISABLED = 0
	RULE_ACTION_DENY     = 1
	OPERATOR_IS          = "=="
	OPERATOR_IS_NOT      = "!="
	RULE_ON              = "on"
	RULE_OFF             = "off"
)
