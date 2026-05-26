package client

import (
	"fmt"
	"net/url"
)

// AppBundle represents an application bundle
type AppBundle struct {
	ResourceURI      ResourceURI       `json:"resource_uri"`
	CreatedAt        string            `json:"created_at"`
	Description      string            `json:"description"`
	ModifiedAt       string            `json:"modified_at"`
	Name             string            `json:"name"`
	SingleHostFQDN   string            `json:"single_host_fqdn"`
	UUIDURL          string            `json:"uuid_url"`
	AppDetails       []AppBundleDetail `json:"app_details"`
	GroupApps        []string          `json:"group_apps"`
	Status           int               `json:"status"`
	SingleHostEnable bool              `json:"single_host_enable"`
}

// AppBundleDetail represents application details within a bundle (renamed to avoid conflict)
type AppBundleDetail struct {
	Localization        string `json:"localization"`
	Name                string `json:"name"`
	SingleHostPath      string `json:"single_host_path"`
	UUIDURL             string `json:"uuid_url"`
	AppOperational      int    `json:"app_operational"`
	AppProfile          int    `json:"app_profile"`
	AppStatus           int    `json:"app_status"`
	AppType             int    `json:"app_type"`
	AppDeployed         bool   `json:"app_deployed"`
	SingleHostContentRW bool   `json:"single_host_content_rw"`
}

// AppBundleResponse represents the API response for app bundles
type AppBundleResponse struct {
	Objects []AppBundle `json:"objects"`
	Meta    Meta        `json:"meta"`
}

const (
	APPBUNDLE_URL = "/crux/v1/mgmt-pop/appbundle"
)

// GetAppBundles fetches app bundles from the API, applying optional query filters
// (e.g. url.Values{"name__icontains": {"my-bundle"}} or url.Values{"uuid_url__in": {"uuid1,uuid2"}}).
func (ec *EaaClient) GetAppBundles(filters ...url.Values) (*AppBundleResponse, error) {
	apiURL := fmt.Sprintf("%s://%s%s", URL_SCHEME, ec.Host, APPBUNDLE_URL)
	if len(filters) > 0 && len(filters[0]) > 0 {
		apiURL = fmt.Sprintf("%s?%s", apiURL, filters[0].Encode())
	}

	var appBundleResp AppBundleResponse
	expand := false
	_, err := ec.SendAPIRequest(apiURL, "GET", nil, &appBundleResp, false, GetRequestOptions{Expand: &expand})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch app bundles: %w", err)
	}

	return &appBundleResp, nil
}

// GetAppBundleByName fetches app bundles filtered by name and returns the UUID for an exact name match.
func (ec *EaaClient) GetAppBundleByName(name string) (string, error) {
	appBundles, err := ec.GetAppBundles(url.Values{"name__icontains": {name}})
	if err != nil {
		return "", err
	}

	for i := range appBundles.Objects {
		if appBundles.Objects[i].Name == name {
			return appBundles.Objects[i].UUIDURL, nil
		}
	}

	return "", fmt.Errorf("app bundle with name '%s' not found", name)
}

// GetAppBundleNameByUUID fetches app bundles filtered by UUID and returns the name for an exact UUID match.
func (ec *EaaClient) GetAppBundleNameByUUID(uuid string) (string, error) {
	appBundles, err := ec.GetAppBundles(url.Values{"uuid_url__in": {uuid}})
	if err != nil {
		return "", err
	}

	for i := range appBundles.Objects {
		if appBundles.Objects[i].UUIDURL == uuid {
			return appBundles.Objects[i].Name, nil
		}
	}

	return "", fmt.Errorf("app bundle with UUID '%s' not found", uuid)
}

// ValidateAppBundleName validates that the app bundle name exists
func (ec *EaaClient) ValidateAppBundleName(name string) error {
	_, err := ec.GetAppBundleByName(name)
	return err
}
