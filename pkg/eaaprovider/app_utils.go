package eaaprovider

import (
	"context"
	"fmt"
	"net/http"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
)

func stringPointerValue(value *string) interface{} {
	if value == nil {
		return nil
	}
	return *value
}

// cleanupOrphanedApp cleans up orphaned apps that may exist in EAA
func cleanupOrphanedApp(ctx context.Context, eaaclient *client.EaaClient, appID string) bool {
	logging.Debug(ctx, "starting cleanup for orphaned app", []logging.Tag{logging.TagApp, logging.TagDelete}, map[string]any{"app_id": appID})

	// Check if app exists in EAA
	var appResp client.ApplicationDataModel
	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, appID)

	getResp, err := eaaclient.SendAPIRequest(ctx, apiURL, "GET", nil, &appResp, false)
	if err != nil {
		logging.Warn(ctx, "failed to check app existence in EAA", []logging.Tag{logging.TagApp, logging.TagDelete}, map[string]any{"error": err, "app_id": appID})
		return false
	}
	if getResp.StatusCode == http.StatusNotFound {
		logging.Debug(ctx, "App not found in EAA, no cleanup needed", []logging.Tag{logging.TagApp, logging.TagDelete})
		return true
	}
	if getResp.StatusCode != http.StatusOK {
		logging.Warn(ctx, "unexpected status while checking app existence in EAA", []logging.Tag{logging.TagApp, logging.TagDelete}, map[string]any{"status_code": getResp.StatusCode, "app_id": appID})
		return false
	}

	logging.Debug(ctx, "App found in EAA, proceeding with deletion...", []logging.Tag{logging.TagApp, logging.TagDelete})

	// Delete the app directly
	deleteErr := appResp.DeleteApplication(ctx, eaaclient)
	if deleteErr != nil {
		logging.Warn(ctx, "failed to delete app during cleanup", []logging.Tag{logging.TagApp, logging.TagDelete}, map[string]any{"error": deleteErr})
		return false
	}

	verifyResp, err := eaaclient.SendAPIRequest(ctx, apiURL, "GET", nil, &appResp, false)
	if err == nil && verifyResp.StatusCode == 200 {
		logging.Warn(ctx, "App still exists after deletion attempt", []logging.Tag{logging.TagApp, logging.TagDelete})
		return false
	}

	logging.Debug(ctx, "App successfully deleted and verified", []logging.Tag{logging.TagApp, logging.TagDelete})
	return true
}
