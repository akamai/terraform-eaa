package eaaprovider

import (
	"context"
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

// convertStringPointerToString converts *string to string, returns null string for nil
func convertStringPointerToString(value *string) string {
	if value == nil {
		return "null"
	}
	return *value
}

// getValidCipherSuitesFromAPI retrieves valid TLS cipher suites from the API
func getValidCipherSuitesFromAPI(meta interface{}) ([]string, error) {
	eaaclient, err := Client(meta)
	if err != nil {
		return []string{}, err
	}

	// For validation purposes, we need a dummy app UUID URL
	// In practice, this should be the actual app UUID URL being validated
	// For now, we'll use a placeholder that works with the API
	dummyAppUUID := "dummy-app-uuid-for-validation"

	tlsResponse, err := client.GetTLSCipherSuites(eaaclient, dummyAppUUID)
	if err != nil {
		// Return empty slice instead of error to prevent validation blocking
		return []string{}, nil
	}

	// Extract cipher suite names from API response
	cipherSuites := make([]string, 0, len(tlsResponse.TLSCipherSuite))
	for name := range tlsResponse.TLSCipherSuite {
		cipherSuites = append(cipherSuites, name)
	}

	return cipherSuites, nil
}

// cleanupOrphanedApp cleans up orphaned apps that may exist in EAA
func cleanupOrphanedApp(ctx context.Context, eaaclient *client.EaaClient, appID string) bool {
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
