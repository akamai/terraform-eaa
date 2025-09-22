package client

import (
	"fmt"
)

// AppBundle represents an application bundle
type AppBundle struct {
	AppDetails       []AppBundleDetail `json:"app_details"`
	CreatedAt        string            `json:"created_at"`
	Description      string            `json:"description"`
	GroupApps        []string          `json:"group_apps"`
	ModifiedAt       string            `json:"modified_at"`
	Name             string            `json:"name"`
	ResourceURI      ResourceURI       `json:"resource_uri"`
	SingleHostEnable bool              `json:"single_host_enable"`
	SingleHostFQDN   string            `json:"single_host_fqdn"`
	Status           int               `json:"status"`
	UUIDURL          string            `json:"uuid_url"`
}

// AppBundleDetail represents application details within a bundle (renamed to avoid conflict)
type AppBundleDetail struct {
	AppDeployed         bool   `json:"app_deployed"`
	AppOperational      int    `json:"app_operational"`
	AppProfile          int    `json:"app_profile"`
	AppStatus           int    `json:"app_status"`
	AppType             int    `json:"app_type"`
	Localization        string `json:"localization"`
	Name                string `json:"name"`
	SingleHostContentRW bool   `json:"single_host_content_rw"`
	SingleHostPath      string `json:"single_host_path"`
	UUIDURL             string `json:"uuid_url"`
}

// AppBundleResponse represents the API response for app bundles
type AppBundleResponse struct {
	Meta    Meta        `json:"meta"`
	Objects []AppBundle `json:"objects"`
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
