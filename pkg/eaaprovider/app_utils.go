package eaaprovider

import (
	"fmt"
	"strconv"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
)

// convertStringToInt converts string to int, returns 0 if conversion fails
func convertStringToInt(value string) int {
	if value == "" {
		return 0
	}
	if i, err := strconv.Atoi(value); err == nil {
		return i
	}
	return 0
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
	logger.Debug("Starting cleanup for orphaned app:", appID)

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
		logger.Error("Failed to delete app during cleanup:", deleteErr)
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
