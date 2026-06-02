package eaaprovider

import (
	"fmt"
	"strconv"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
)

func convertStringToInt(value string) (int, error) {
	if value == "" {
		return 0, nil
	}
	i, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("cannot convert %q to int: %w", value, err)
	}
	return i, nil
}

func stringPointerValue(value *string) interface{} {
	if value == nil {
		return nil
	}
	return *value
}

// cleanupOrphanedApp cleans up orphaned apps that may exist in EAA
func cleanupOrphanedApp(eaaclient *client.EaaClient, appID string) bool {
	logger := eaaclient.Logger
	logger.Debug("starting cleanup for orphaned app", "app_id", appID)

	// Check if app exists in EAA
	var appResp client.ApplicationDataModel
	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, appID)

	getResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
	if err != nil || getResp.StatusCode != 200 {
		logger.Debug("App not found in EAA, no cleanup needed")
		return true
	}

	logger.Debug("App found in EAA, proceeding with deletion...")

	// Delete the app directly
	deleteErr := appResp.DeleteApplication(eaaclient)
	if deleteErr != nil {
		logger.Error("failed to delete app during cleanup", "error", deleteErr)
		return false
	}

	verifyResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
	if err == nil && verifyResp.StatusCode == 200 {
		logger.Error("App still exists after deletion attempt")
		return false
	}

	logger.Debug("App successfully deleted and verified")
	return true
}
