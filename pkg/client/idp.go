package client

import (
	"context"
	"fmt"
	"net/http"

	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
)

type IDPCreateRequest struct {
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	Localization string `json:"localization,omitempty"`
	IDPType      int    `json:"idp_type,omitempty"`
}

type IDPFullResponse struct {
	CustomTLSSuiteName               *string                `json:"custom_tls_suite_name,omitempty"`
	MultilangFields                  map[string]interface{} `json:"multilang_fields,omitempty"`
	LoginLockout                     *string                `json:"login_lockout,omitempty"`
	MaxLoginFailures                 *int                   `json:"max_login_failures,omitempty"`
	LockoutInterval                  *int                   `json:"lockout_interval,omitempty"`
	CookieExpiry                     *int                   `json:"cookie_expiry,omitempty"`
	TrustExpiry                      *int                   `json:"trust_expiry,omitempty"`
	ClientPrincipleName              *string                `json:"client_principle_name,omitempty"`
	Cert                             *string                `json:"cert,omitempty"`
	ClientCert                       *string                `json:"client_cert,omitempty"`
	Pop                              *string                `json:"pop,omitempty"`
	FailoverPop                      *string                `json:"failover_pop,omitempty"`
	AttributeMap                     map[string]interface{} `json:"attribute_map,omitempty"`
	Settings                         map[string]interface{} `json:"settings,omitempty"`
	MFASettings                      map[string]interface{} `json:"mfa_settings,omitempty"`
	EnableMFA                        *bool                  `json:"enable_mfa,omitempty"`
	ETPEnabled                       *bool                  `json:"etp_enabled,omitempty"`
	EnableAccessClient               *bool                  `json:"enable_access_client,omitempty"`
	GCClientEnabled                  *bool                  `json:"gc_client_enabled,omitempty"`
	AuthRequestSigned                *bool                  `json:"auth_request_signed,omitempty"`
	AuthResponseEncrypt              *bool                  `json:"auth_response_encrypt,omitempty"`
	SAMLCertType                     *int                   `json:"saml_cert_type,omitempty"`
	SAMLIDPCustomSignCert            *string                `json:"saml_idp_custom_sign_cert,omitempty"`
	SAMLUrl                          *string                `json:"saml_url,omitempty"`
	LogoutURL                        *string                `json:"logout_url,omitempty"`
	HelpdeskEmail                    *string                `json:"helpdesk_email,omitempty"`
	DefaultLanguage                  *string                `json:"default_language,omitempty"`
	DefaultTLSSuite                  *bool                  `json:"default_tls_suite,omitempty"`
	LoginDomain                      *int                   `json:"login_domain,omitempty"`
	LoginHost                        *string                `json:"login_host,omitempty"`
	PostLogoutRedirectCustomURL      *string                `json:"post_logout_redirect_custom_url,omitempty"`
	AgentInstallationProfile         *bool                  `json:"agent_installation_profile,omitempty"`
	Source                           *string                `json:"source,omitempty"`
	PostAuthFailureRedirectType      *string                `json:"post_auth_failure_redirect_type,omitempty"`
	PostAuthFailureRedirectCustomURL *string                `json:"post_auth_failure_redirect_custom_url,omitempty"`
	PostLogoutRedirectType           *string                `json:"post_logout_redirect_type,omitempty"`
	ModifiedAt                       string                 `json:"modified_at,omitempty"`
	CreatedAt                        string                 `json:"created_at,omitempty"`
	Description                      string                 `json:"description,omitempty"`
	Name                             string                 `json:"name,omitempty"`
	PopName                          string                 `json:"popName,omitempty"`
	TLSSuiteName                     string                 `json:"tls_suite_name,omitempty"`
	UUIDURL                          string                 `json:"uuid_url,omitempty"`
	Localization                     string                 `json:"localization,omitempty"`
	ClientHost                       string                 `json:"client_host,omitempty"`
	CompanyID                        string                 `json:"company_id,omitempty"`
	LoginSuffix                      string                 `json:"login_suffix,omitempty"`
	DomainSuffix                     string                 `json:"domain_suffix,omitempty"`
	LoginCName                       string                 `json:"login_cname,omitempty"`
	LoginDialinServer                string                 `json:"login_dialin_server,omitempty"`
	Domains                          []string               `json:"domains,omitempty"`
	Status                           int                    `json:"status,omitempty"`
	IDPStatus                        int                    `json:"idp_status,omitempty"`
	IDPOperational                   int                    `json:"idp_operational,omitempty"`
	DirectoryCount                   int                    `json:"directory_count,omitempty"`
	AppCount                         int                    `json:"app_count,omitempty"`
	IDPType                          int                    `json:"idp_type,omitempty"`
	DNSAdded                         bool                   `json:"dns_added,omitempty"`
	IDPDeployed                      bool                   `json:"idp_deployed,omitempty"`
}

type IDPData struct {
	Name        string          `json:"name"`
	UUIDURL     string          `json:"uuid_url"`
	Directories []DirectoryData `json:"directories_list,omitempty"`
}

type IDPList struct {
	IDPS []IDPData `json:"objects,omitempty"`
}

type IDPResponseData struct {
	Name    string `json:"name"`
	UUIDURL string `json:"uuid_url"`
}

type IDPResponse struct {
	IDPS []IDPResponseData `json:"objects,omitempty"`
	Meta Meta              `json:"meta,omitempty"`
}

type DirectoryResponse struct {
	DirectoryList []DirectoryData `json:"objects,omitempty"`
	Meta          Meta            `json:"meta,omitempty"`
}

type Meta struct {
	Next       *string `json:"next,omitempty"`
	Previous   *string `json:"previous,omitempty"`
	Limit      int     `json:"limit,omitempty"`
	Offset     int     `json:"offset,omitempty"`
	TotalCount int     `json:"total_count,omitempty"`
}

func GetIDPS(ctx context.Context, ec *EaaClient) (*IDPList, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagIDP, logging.TagList}
	logging.Info(ctx, "getIDPs call", tags)

	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, IDP_URL)
	logging.Debug(ctx, "api URL", tags, map[string]any{"url": apiURL})

	idpResponse := IDPResponse{}
	getResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &idpResponse, false)
	if err != nil {
		return nil, err
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(getResp)
		return nil, logging.Errorf(tags, "idps get failed: %s", desc)
	}

	idpList := IDPList{}
	idps := []IDPData{}
	for _, idp := range idpResponse.IDPS {
		if idp.Name == "" || idp.UUIDURL == "" {
			continue
		}
		directoryList, err := GetIDPDirectories(ctx, ec, idp.UUIDURL)
		if err != nil {
			return nil, logging.Wrapf(err, tags, "failed to get directories for IDP '%s'", idp.Name)
		}
		idpData := IDPData{
			Name:        idp.Name,
			UUIDURL:     idp.UUIDURL,
			Directories: directoryList,
		}
		idps = append(idps, idpData)
	}
	idpList.IDPS = idps
	return &idpList, nil
}

func GetIdpWithName(ctx context.Context, ec *EaaClient, idpName string) (*IDPData, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagIDP, logging.TagRead}
	logging.Info(ctx, "GetIdpWithName", tags, map[string]any{"idp_name": idpName})

	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, IDP_URL)
	logging.Debug(ctx, "api URL", tags, map[string]any{"url": apiURL})

	idpResponse := IDPResponse{}
	getResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &idpResponse, false)
	if err != nil {
		return nil, err
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(getResp)
		return nil, logging.Errorf(tags, "idps get failed: %s", desc)
	}

	for _, idp := range idpResponse.IDPS {
		if idp.Name == idpName {
			directoryList, err := GetIDPDirectories(ctx, ec, idp.UUIDURL)
			if err != nil {
				return nil, logging.Wrapf(err, tags, "failed to get directories for IDP '%s'", idpName)
			}
			idpData := IDPData{
				Name:        idp.Name,
				UUIDURL:     idp.UUIDURL,
				Directories: directoryList,
			}
			return &idpData, nil
		}
	}

	return nil, logging.Errorf(tags, "IDP with name '%s' not found", idpName)
}

func (idpData *IDPData) GetIdpDirectory(ctx context.Context, ec *EaaClient, dirName string) (*DirectoryData, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagIDP, logging.TagRead}

	for _, directory := range idpData.Directories {
		if dirName == directory.Name {
			logging.Info(ctx, "directory found", tags, map[string]any{"name": directory.Name})
			return &directory, nil
		}
	}

	return nil, logging.Errorf(tags, "IDP Directory with name '%s' not found", dirName)
}

func GetIDPDirectories(ctx context.Context, ec *EaaClient, idpUUID string) ([]DirectoryData, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagIDP, logging.TagList}
	apiURL := fmt.Sprintf("%s://%s/%s/%s/directories", URL_SCHEME, ec.Host, IDP_URL, idpUUID)
	logging.Info(ctx, "getIDPDirectories", tags, map[string]any{"idp_uuid": idpUUID})
	logging.Debug(ctx, "api URL", tags, map[string]any{"url": apiURL})
	directoryResponse := DirectoryResponse{}

	getResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &directoryResponse, false)
	if err != nil {
		return nil, err
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(getResp)
		return nil, logging.Errorf(tags, "idp directories get failed: %s", desc)
	}

	directoryList := []DirectoryData{}
	for _, directory := range directoryResponse.DirectoryList {
		if directory.Name == "" || directory.UUID == "" {
			continue
		}
		groupList := []GroupData{}
		for _, group := range directory.Groups {
			if group.Name == "" || group.UUID_URL == "" {
				continue
			}
			groupData := GroupData{
				Name:     group.Name,
				UUID_URL: group.UUID_URL,
			}
			groupList = append(groupList, groupData)
		}

		directoryData := DirectoryData{
			Name:   directory.Name,
			UUID:   directory.UUID,
			Groups: groupList,
		}
		directoryList = append(directoryList, directoryData)
	}
	return directoryList, nil
}

func (idpData *IDPData) AssignIdpDirectories(ctx context.Context, appDirs interface{}, appUUIDURL string, ec *EaaClient) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagIDP, logging.TagAssign}
	logging.Info(ctx, "assigning directories to application", tags)

	if appDirsList, ok := appDirs.([]interface{}); ok {
		for _, s := range appDirsList {
			if sData, ok := s.(map[string]interface{}); ok {
				appdir := AppDirectory{}
				if dirName, ok := sData["name"].(string); ok {
					logging.Info(ctx, dirName, tags)
					if em, ok := sData["enable_mfa"].(bool); ok {
						appdir.EnableMFA = &em
					}
					dirData, err := idpData.GetIdpDirectory(ctx, ec, dirName)
					if err != nil {
						logging.Error(ctx, "directory not found", tags, map[string]any{"name": dirName, "error": err})
						return logging.Wrapf(err, tags, "directory '%s' not found in IDP", dirName)
					}
					appdir.UUID = dirData.UUID
					appdir.APP_ID = appUUIDURL
					err = appdir.AssignIdpDirectory(ctx, ec)
					if err != nil {
						logging.Info(ctx, "directory assignment failed", tags)
						return err
					}

					if appGroupsList, ok := sData["app_groups"].([]interface{}); ok {
						if len(appGroupsList) > 0 {
							err = dirData.AssignIdpDirectoryGroups(ctx, ec, appUUIDURL, appGroupsList)
						} else {
							err = dirData.AssignAllDirectoryGroups(ctx, ec, appUUIDURL)
						}
						if err != nil {
							logging.Info(ctx, "directory groups assignment failed", tags)
							return err
						}
					}
				}
			}
		}
	}
	return nil
}

func CreateIDP(ctx context.Context, ec *EaaClient, req *IDPCreateRequest) (*IDPFullResponse, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagIDP, logging.TagCreate}
	logging.Info(ctx, "creating IDP", tags, map[string]any{"name": req.Name})

	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, IDP_URL)

	var resp IDPFullResponse
	httpResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", req, &resp, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "create IDP API request failed")
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(httpResp)
		return nil, logging.Wrapf(ErrIDPCreate, tags, "HTTP %d: %s", httpResp.StatusCode, desc)
	}

	logging.Info(ctx, "IDP created", tags, map[string]any{"uuid": resp.UUIDURL})
	return &resp, nil
}

func GetIDP(ctx context.Context, ec *EaaClient, uuid string) (*IDPFullResponse, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagIDP, logging.TagRead}
	logging.Info(ctx, "getting IDP", tags, map[string]any{"uuid": uuid})

	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, IDP_URL, uuid)

	var resp IDPFullResponse
	httpResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &resp, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "get IDP API request failed")
	}
	if httpResp.StatusCode == http.StatusNotFound {
		return nil, logging.Wrapf(ErrIDPNotFound, tags, "IDP '%s' not found", uuid)
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(httpResp)
		return nil, logging.Wrapf(ErrIDPGet, tags, "HTTP %d: %s", httpResp.StatusCode, desc)
	}

	return &resp, nil
}

func UpdateIDP(ctx context.Context, ec *EaaClient, uuid string, body *IDPFullResponse) (*IDPFullResponse, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagIDP, logging.TagUpdate}
	logging.Info(ctx, "updating IDP", tags, map[string]any{"uuid": uuid})

	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, IDP_URL, uuid)

	var resp IDPFullResponse
	httpResp, err := ec.SendAPIRequest(ctx, apiURL, "PUT", body, &resp, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "update IDP API request failed")
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(httpResp)
		return nil, logging.Wrapf(ErrIDPUpdate, tags, "HTTP %d: %s", httpResp.StatusCode, desc)
	}

	return &resp, nil
}

func DeleteIDP(ctx context.Context, ec *EaaClient, uuid string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagIDP, logging.TagDelete}
	logging.Info(ctx, "deleting IDP", tags, map[string]any{"uuid": uuid})

	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, IDP_URL, uuid)

	httpResp, err := ec.SendAPIRequest(ctx, apiURL, "DELETE", nil, nil, false)
	if err != nil {
		return logging.Wrapf(err, tags, "delete IDP API request failed")
	}
	if httpResp.StatusCode != http.StatusNoContent &&
		(httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices) {
		desc := FormatErrorDescription(httpResp)
		return logging.Wrapf(ErrIDPDelete, tags, "HTTP %d: %s", httpResp.StatusCode, desc)
	}

	logging.Info(ctx, "IDP deleted", tags, map[string]any{"uuid": uuid})
	return nil
}

func DeployIDP(ctx context.Context, ec *EaaClient, uuid string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagIDP, logging.TagDeploy}
	logging.Info(ctx, "deploying IDP", tags, map[string]any{"uuid": uuid})

	apiURL := fmt.Sprintf("%s://%s/%s/%s/deploy", URL_SCHEME, ec.Host, IDP_URL, uuid)
	data := map[string]string{
		"deploy_note": "deploying the IDP managed through terraform",
	}

	var statusResp map[string]interface{}
	httpResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", data, &statusResp, false)
	if err != nil {
		return logging.Wrapf(err, tags, "deploy IDP API request failed")
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(httpResp)
		return logging.Wrapf(ErrIDPDeploy, tags, "HTTP %d: %s", httpResp.StatusCode, desc)
	}

	logging.Info(ctx, "IDP deployment triggered", tags, map[string]any{"uuid": uuid})
	return nil
}

func GetPopByName(ctx context.Context, ec *EaaClient, popName string) (*Pop, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagPopTraffic, logging.TagRead}

	pops, err := GetPops(ctx, ec)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "failed to get pops")
	}
	for i := range pops {
		if pops[i].Name == popName {
			return &pops[i], nil
		}
	}
	return nil, logging.Errorf(tags, "PoP with name '%s' not found", popName)
}
