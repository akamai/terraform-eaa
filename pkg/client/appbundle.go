package client

import (
	"fmt"
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

// GetAppBundles fetches all app bundles from the API
func (ec *EaaClient) GetAppBundles() (*AppBundleResponse, error) {
	apiURL := fmt.Sprintf("%s://%s%s", URL_SCHEME, ec.Host, APPBUNDLE_URL)

	var appBundleResp AppBundleResponse
	_, err := ec.SendAPIRequest(apiURL, "GET", nil, &appBundleResp, false)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch app bundles: %w", err)
	}

	return &appBundleResp, nil
}

// GetAppBundleByName finds an app bundle by name and returns its UUID
func (ec *EaaClient) GetAppBundleByName(name string) (string, error) {
	appBundles, err := ec.GetAppBundles()
	if err != nil {
		return "", fmt.Errorf("failed to fetch app bundles: %w", err)
	}

	for _, bundle := range appBundles.Objects {
		if bundle.Name == name {
			return bundle.UUIDURL, nil
		}
	}

	return "", fmt.Errorf("app bundle with name '%s' not found", name)
}

// ValidateAppBundleName validates that the app bundle name exists
func (ec *EaaClient) ValidateAppBundleName(name string) error {
	_, err := ec.GetAppBundleByName(name)
	return err
}
