package client

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
)

const (
	directoryPollInterval = 5 * time.Second
	directoryPollTimeout  = 2 * time.Minute
)

type DirectoryCreateRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Service     int    `json:"service"`
	IsLedaDir   bool   `json:"is_leda_dir"`
}

type DirectoryGroupEntry struct {
	Name    string `json:"name"`
	UUIDURL string `json:"uuid_url"`
}

type DirectoryFullResponse struct {
	AttributeMap             map[string]interface{} `json:"attribute_map,omitempty"`
	PasswordFilter           map[string]interface{} `json:"password_filter,omitempty"`
	ScimProviderID           string                 `json:"scim_provider_id,omitempty"`
	AdminUser                string                 `json:"admin_user,omitempty"`
	ModifiedAt               string                 `json:"modified_at,omitempty"`
	Localization             string                 `json:"localization,omitempty"`
	CName                    string                 `json:"cname,omitempty"`
	DialinSNI                string                 `json:"dialin_sni,omitempty"`
	LastSync                 string                 `json:"last_sync,omitempty"`
	Host                     string                 `json:"host,omitempty"`
	RootDN                   string                 `json:"root_dn,omitempty"`
	Description              string                 `json:"description,omitempty"`
	AdminPwd                 string                 `json:"admin_pwd,omitempty"`
	MFA                      string                 `json:"mfa,omitempty"`
	LogoutURL                string                 `json:"logout_url,omitempty"`
	UserBaseDN               string                 `json:"user_base_dn,omitempty"`
	UserSearchFilter         string                 `json:"user_search_filter,omitempty"`
	UserDisplayName          string                 `json:"user_display_name,omitempty"`
	UserEmail                string                 `json:"user_email,omitempty"`
	UserFname                string                 `json:"user_fname,omitempty"`
	UserLname                string                 `json:"user_lname,omitempty"`
	UserPhoneNum             string                 `json:"user_phone_num,omitempty"`
	UserPrincipal            string                 `json:"user_principal,omitempty"`
	UserSamaccountname       string                 `json:"user_samaccountname,omitempty"`
	UserUPN                  string                 `json:"user_upn,omitempty"`
	UserMemberof             string                 `json:"user_memberof,omitempty"`
	UserMemberuid            string                 `json:"user_memberuid,omitempty"`
	GroupBaseDN              string                 `json:"group_base_dn,omitempty"`
	GroupSearchFilter        string                 `json:"group_search_filter,omitempty"`
	GroupMembers             string                 `json:"group_members,omitempty"`
	GroupName                string                 `json:"group_name,omitempty"`
	GroupToken               string                 `json:"group_token,omitempty"`
	OUAttr                   string                 `json:"ou_attr,omitempty"`
	OUFilter                 string                 `json:"ou_filter,omitempty"`
	PasswordPolicyDefault    string                 `json:"password_policy_default,omitempty"`
	PasswordComplexityMsg    string                 `json:"password_complexity_message,omitempty"`
	Name                     string                 `json:"name,omitempty"`
	CompanyID                string                 `json:"company_id,omitempty"`
	CreatedAt                string                 `json:"created_at,omitempty"`
	UUIDURL                  string                 `json:"uuid_url,omitempty"`
	Source                   string                 `json:"source,omitempty"`
	Groups                   []DirectoryGroupEntry  `json:"groups,omitempty"`
	UserObjectClasses        []string               `json:"user_object_classes,omitempty"`
	GroupObjectClasses       []string               `json:"group_object_classes,omitempty"`
	ConnectorPools           []interface{}          `json:"connector_pools,omitempty"`
	Agents                   []Connector            `json:"agents,omitempty"`
	KerbRealms               []interface{}          `json:"kerb_realms,omitempty"`
	Domains                  []string               `json:"domains,omitempty"`
	HostAliases              []string               `json:"host_aliases,omitempty"`
	OUObjectClasses          []string               `json:"ou_object_classes,omitempty"`
	SyncInterval             int                    `json:"sync_interval,omitempty"`
	Service                  int                    `json:"service,omitempty"`
	UserCount                int                    `json:"user_count,omitempty"`
	GroupCount               int                    `json:"group_count,omitempty"`
	PasswordExpireWarn       int                    `json:"password_expire_warn_threshold,omitempty"`
	PasswordChangeThreshold  int                    `json:"password_change_threshold,omitempty"`
	Status                   int                    `json:"status,omitempty"`
	RateLimitQueryCount      int                    `json:"rate_limit_query_count,omitempty"`
	Port                     int                    `json:"port,omitempty"`
	DirectoryType            int                    `json:"directory_type,omitempty"`
	DirectoryStatus          int                    `json:"directory_status,omitempty"`
	DirectoryDeployedStatus  int                    `json:"directory_deployed_status,omitempty"`
	SyncState                int                    `json:"sync_state,omitempty"`
	RateLimitTimeInterval    int                    `json:"rate_limit_time_interval,omitempty"`
	AuthRequestSigned        bool                   `json:"auth_request_signed,omitempty"`
	ServerCertValidate       bool                   `json:"server_cert_validate,omitempty"`
	GlobalCatalog            bool                   `json:"global_catalog,omitempty"`
	ChaseReferral            bool                   `json:"chase_referral,omitempty"`
	IsSSLVerificationEnabled bool                   `json:"is_ssl_verification_enabled,omitempty"`
	SSL                      bool                   `json:"ssl,omitempty"`
	AuthResponseEncrypt      bool                   `json:"auth_response_encrypt,omitempty"`
	PasswordChangeAllow      bool                   `json:"password_change_allow,omitempty"`
	PasswordResetAllow       bool                   `json:"password_reset_allow,omitempty"`
	IsRateLimitEnabled       bool                   `json:"is_rate_limit_enabled,omitempty"`
	IsLedaDir                bool                   `json:"is_leda_dir,omitempty"`
}

type VerifyResponse struct {
	CmdID         string `json:"cmdid"`
	Status        string `json:"status"`
	DirReachError string `json:"dir_reach_error,omitempty"`
	Message       string `json:"message,omitempty"`
	DirStatus     int    `json:"dir_status"`
	Code          int    `json:"code,omitempty"`
}

type SearchResponse struct {
	CmdID  string `json:"cmdid"`
	Status string `json:"status"`
}

type SearchGroupResult struct {
	Name       string `json:"name"`
	DN         string `json:"dn"`
	ExternalID string `json:"external_id"`
	Assigned   bool   `json:"assigned"`
}

type SearchStatusResponse struct {
	Status  string              `json:"status"`
	Message string              `json:"message,omitempty"`
	Data    []SearchGroupResult `json:"data"`
	Code    int                 `json:"code,omitempty"`
}

type DirectoryGroupAssignRequest struct {
	Name       string `json:"name"`
	DN         string `json:"dn"`
	ExternalID string `json:"external_id"`
	Assigned   bool   `json:"assigned"`
}

type DirectoryGroupsResponse struct {
	Objects []DirectoryGroupEntry `json:"objects"`
	Meta    Meta                  `json:"meta,omitempty"`
}

func CreateDirectory(ctx context.Context, ec *EaaClient, req *DirectoryCreateRequest) (*DirectoryFullResponse, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagDirectory, logging.TagCreate}
	logging.Info(ctx, "creating directory", tags, map[string]any{"name": req.Name})

	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, DIRECTORIES_URL)

	var resp DirectoryFullResponse
	httpResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", req, &resp, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "create directory API request failed")
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(httpResp)
		return nil, logging.Wrapf(ErrDirectoryCreate, tags, "HTTP %d: %s", httpResp.StatusCode, desc)
	}

	logging.Info(ctx, "directory created", tags, map[string]any{"uuid": resp.UUIDURL})
	return &resp, nil
}

func GetDirectory(ctx context.Context, ec *EaaClient, uuid string) (*DirectoryFullResponse, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagDirectory, logging.TagRead}
	logging.Info(ctx, "getting directory", tags, map[string]any{"uuid": uuid})

	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, DIRECTORIES_URL, uuid)

	var resp DirectoryFullResponse
	httpResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &resp, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "get directory API request failed")
	}
	if httpResp.StatusCode == http.StatusNotFound {
		return nil, logging.Wrapf(ErrDirectoryNotFound, tags, "directory '%s' not found", uuid)
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(httpResp)
		return nil, logging.Wrapf(ErrDirectoryGet, tags, "HTTP %d: %s", httpResp.StatusCode, desc)
	}

	return &resp, nil
}

func UpdateDirectory(ctx context.Context, ec *EaaClient, uuid string, body *DirectoryFullResponse) (*DirectoryFullResponse, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagDirectory, logging.TagUpdate}
	logging.Info(ctx, "updating directory", tags, map[string]any{"uuid": uuid})

	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, DIRECTORIES_URL, uuid)

	var resp DirectoryFullResponse
	httpResp, err := ec.SendAPIRequest(ctx, apiURL, "PUT", body, &resp, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "update directory API request failed")
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(httpResp)
		return nil, logging.Wrapf(ErrDirectoryUpdate, tags, "HTTP %d: %s", httpResp.StatusCode, desc)
	}

	return &resp, nil
}

func DeleteDirectory(ctx context.Context, ec *EaaClient, uuid string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagDirectory, logging.TagDelete}
	logging.Info(ctx, "deleting directory", tags, map[string]any{"uuid": uuid})

	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, DIRECTORIES_URL, uuid)

	httpResp, err := ec.SendAPIRequest(ctx, apiURL, "DELETE", nil, nil, false)
	if err != nil {
		return logging.Wrapf(err, tags, "delete directory API request failed")
	}
	if httpResp.StatusCode != http.StatusNoContent &&
		(httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices) {
		desc := FormatErrorDescription(httpResp)
		return logging.Wrapf(ErrDirectoryDelete, tags, "HTTP %d: %s", httpResp.StatusCode, desc)
	}

	logging.Info(ctx, "directory deleted", tags, map[string]any{"uuid": uuid})
	return nil
}

func VerifyDirectory(ctx context.Context, ec *EaaClient, uuid string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagDirectory, logging.TagValidate}
	logging.Info(ctx, "verifying directory", tags, map[string]any{"uuid": uuid})

	apiURL := fmt.Sprintf("%s://%s/%s/%s/verify", URL_SCHEME, ec.Host, DIRECTORIES_URL, uuid)
	var verifyResp VerifyResponse
	httpResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", map[string]interface{}{}, &verifyResp, false)
	if err != nil {
		return logging.Wrapf(err, tags, "verify directory API request failed")
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(httpResp)
		return logging.Wrapf(ErrDirectoryVerify, tags, "HTTP %d: %s", httpResp.StatusCode, desc)
	}

	cmdID := verifyResp.CmdID
	logging.Info(ctx, "verify initiated", tags, map[string]any{"cmdid": cmdID})

	checkURL := fmt.Sprintf("%s://%s/%s/%s/verify/%s", URL_SCHEME, ec.Host, DIRECTORIES_URL, uuid, cmdID)
	deadline := time.Now().Add(directoryPollTimeout)

	for time.Now().Before(deadline) {
		time.Sleep(directoryPollInterval)

		var statusResp VerifyResponse
		statusHTTP, statusErr := ec.SendAPIRequest(ctx, checkURL, "GET", nil, &statusResp, false)
		if statusErr != nil {
			return logging.Wrapf(statusErr, tags, "verify status check failed")
		}
		if statusHTTP.StatusCode < http.StatusOK || statusHTTP.StatusCode >= http.StatusMultipleChoices {
			desc := FormatErrorDescription(statusHTTP)
			return logging.Wrapf(ErrDirectoryVerify, tags, "verify status HTTP %d: %s", statusHTTP.StatusCode, desc)
		}

		if statusResp.Code != 0 {
			msg := statusResp.Message
			if msg == "" {
				msg = fmt.Sprintf("error code %d", statusResp.Code)
			}
			return logging.Wrapf(ErrDirectoryVerify, tags, "directory verify failed: %s", msg)
		}

		if statusResp.Status == "complete" {
			if statusResp.DirReachError != "" {
				return logging.Wrapf(ErrDirectoryVerify, tags, "directory verify completed with error: %s", statusResp.DirReachError)
			}
			logging.Info(ctx, "directory verified", tags, map[string]any{"uuid": uuid})
			return nil
		}
	}

	return logging.Wrapf(ErrDirectoryVerifyTimeout, tags, "directory verify timed out after %s", directoryPollTimeout)
}

func SearchDirectoryGroup(ctx context.Context, ec *EaaClient, dirUUID, groupName string) (*SearchGroupResult, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagDirectory, logging.TagRead}
	logging.Info(ctx, "searching directory group", tags, map[string]any{"dir_uuid": dirUUID, "group": groupName})

	searchURL := fmt.Sprintf("%s://%s/%s/%s/search", URL_SCHEME, ec.Host, DIRECTORIES_URL, dirUUID)
	var searchResp SearchResponse
	httpResp, err := ec.SendAPIRequest(ctx, searchURL, "POST", map[string]string{"group": groupName}, &searchResp, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "search directory group API request failed")
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(httpResp)
		return nil, logging.Wrapf(ErrDirectorySearch, tags, "HTTP %d: %s", httpResp.StatusCode, desc)
	}

	cmdID := searchResp.CmdID

	statusURL := fmt.Sprintf("%s://%s/%s/%s/status", URL_SCHEME, ec.Host, DIRECTORIES_URL, dirUUID)
	deadline := time.Now().Add(directoryPollTimeout)

	for time.Now().Before(deadline) {
		time.Sleep(directoryPollInterval)

		var statusResp SearchStatusResponse
		statusHTTP, statusErr := ec.SendAPIRequest(ctx, statusURL, "POST", map[string]string{"cmdid": cmdID}, &statusResp, false)
		if statusErr != nil {
			return nil, logging.Wrapf(statusErr, tags, "search status check failed")
		}
		if statusHTTP.StatusCode < http.StatusOK || statusHTTP.StatusCode >= http.StatusMultipleChoices {
			desc := FormatErrorDescription(statusHTTP)
			return nil, logging.Wrapf(ErrDirectorySearch, tags, "search status HTTP %d: %s", statusHTTP.StatusCode, desc)
		}

		if statusResp.Code != 0 {
			msg := statusResp.Message
			if msg == "" {
				msg = fmt.Sprintf("error code %d", statusResp.Code)
			}
			return nil, logging.Wrapf(ErrDirectorySearch, tags, "group search failed: %s", msg)
		}

		if statusResp.Status == "SUCCESS" {
			if len(statusResp.Data) == 0 {
				return nil, logging.Wrapf(ErrDirectorySearch, tags, "group '%s' not found in directory", groupName)
			}
			return &statusResp.Data[0], nil
		}
	}

	return nil, logging.Wrapf(ErrDirectorySearchTimeout, tags, "group search timed out after %s", directoryPollTimeout)
}

func AssignDirectoryGroup(ctx context.Context, ec *EaaClient, dirUUID string, group *SearchGroupResult) (*DirectoryGroupEntry, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagDirectory, logging.TagAssign}
	logging.Info(ctx, "assigning group to directory", tags, map[string]any{"dir_uuid": dirUUID, "group": group.Name})

	apiURL := fmt.Sprintf("%s://%s/%s/%s/groups", URL_SCHEME, ec.Host, DIRECTORIES_URL, dirUUID)
	req := DirectoryGroupAssignRequest{
		Name:       group.Name,
		DN:         group.DN,
		ExternalID: group.ExternalID,
		Assigned:   false,
	}

	var resp DirectoryGroupEntry
	httpResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", &req, &resp, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "assign group API request failed")
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(httpResp)
		return nil, logging.Wrapf(ErrDirectoryGroupAssign, tags, "HTTP %d: %s", httpResp.StatusCode, desc)
	}

	logging.Info(ctx, "group assigned", tags, map[string]any{"group": resp.Name, "uuid": resp.UUIDURL})
	return &resp, nil
}

func GetDirectoryGroups(ctx context.Context, ec *EaaClient, dirUUID string) ([]DirectoryGroupEntry, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagDirectory, logging.TagList}
	logging.Info(ctx, "getting directory groups", tags, map[string]any{"dir_uuid": dirUUID})

	var allGroups []DirectoryGroupEntry
	apiURL := fmt.Sprintf("%s://%s/%s/%s/groups", URL_SCHEME, ec.Host, DIRECTORIES_URL, dirUUID)

	for apiURL != "" {
		var resp DirectoryGroupsResponse
		httpResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &resp, false)
		if err != nil {
			return nil, logging.Wrapf(err, tags, "get directory groups API request failed")
		}
		if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
			desc := FormatErrorDescription(httpResp)
			return nil, logging.Wrapf(ErrDirectoryGet, tags, "get directory groups failed: %s", desc)
		}

		allGroups = append(allGroups, resp.Objects...)

		if resp.Meta.Next != nil {
			nextURL := *resp.Meta.Next
			nextURL = strings.TrimPrefix(nextURL, "/api/v1")
			apiURL = fmt.Sprintf("%s://%s/%s%s", URL_SCHEME, ec.Host, MGMT_POP_URL, nextURL)
		} else {
			apiURL = ""
		}
	}

	return allGroups, nil
}

func RemoveDirectoryGroup(ctx context.Context, ec *EaaClient, dirUUID, groupUUID string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagDirectory, logging.TagDelete}
	logging.Info(ctx, "removing group from directory", tags, map[string]any{"dir_uuid": dirUUID, "group_uuid": groupUUID})

	apiURL := fmt.Sprintf("%s://%s/%s/%s/groups/%s", URL_SCHEME, ec.Host, DIRECTORIES_URL, dirUUID, groupUUID)

	httpResp, err := ec.SendAPIRequest(ctx, apiURL, "DELETE", nil, nil, false)
	if err != nil {
		return logging.Wrapf(err, tags, "remove group API request failed")
	}
	if httpResp.StatusCode != http.StatusNoContent &&
		(httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices) {
		desc := FormatErrorDescription(httpResp)
		return logging.Wrapf(ErrDirectoryGroupRemove, tags, "HTTP %d: %s", httpResp.StatusCode, desc)
	}

	logging.Info(ctx, "group removed", tags, map[string]any{"group_uuid": groupUUID})
	return nil
}

func SyncDirectory(ctx context.Context, ec *EaaClient, uuid string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagDirectory, logging.TagUpdate}
	logging.Info(ctx, "syncing directory", tags, map[string]any{"uuid": uuid})

	apiURL := fmt.Sprintf("%s://%s/%s/%s/sync", URL_SCHEME, ec.Host, DIRECTORIES_URL, uuid)
	var resp map[string]interface{}
	httpResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", map[string]interface{}{}, &resp, false)
	if err != nil {
		return logging.Wrapf(err, tags, "sync directory API request failed")
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(httpResp)
		return logging.Wrapf(ErrDirectorySync, tags, "HTTP %d: %s", httpResp.StatusCode, desc)
	}

	logging.Info(ctx, "directory sync triggered", tags, map[string]any{"uuid": uuid})
	return nil
}
