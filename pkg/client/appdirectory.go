package client

import (
	"context"
	"fmt"
	"net/http"

	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
)

type GroupData struct {
	Name     string `json:"name"`
	UUID_URL string `json:"uuid_url"`
}

type DirectoryData struct {
	Name   string      `json:"name"`
	UUID   string      `json:"uuid_url"`
	Groups []GroupData `json:"groups,omitempty"`
}

type AppDirectory struct {
	EnableMFA *bool  `json:"enable_mfa,omitempty"`
	APP_ID    string `json:"app_id,omitempty"`
	UUID      string `json:"uuid_url,omitempty"`
}

type AppGroup struct {
	EnableMFA *string `json:"enable_mfa,omitempty"`
	UUIDURL   string  `json:"uuid_url,omitempty"`
}

// AssignIdpDirectory method assigns an IDP directory to an application.
func (dirData *AppDirectory) AssignIdpDirectory(ctx context.Context, ec *EaaClient) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagDirectory, logging.TagAssign}
	logging.Info(ctx, "assign IDP directory", tags)

	if dirData.APP_ID == "" || dirData.UUID == "" {
		logging.Warn(ctx, "assign directories to application failed: app or dir is empty", tags)
		return logging.Wrapf(ErrAssignDirectoryFailure, tags, "app or dir is empty")
	}
	var directories []map[string]interface{}

	directory := map[string]interface{}{
		"uuid_url":   dirData.UUID,
		"enable_mfa": dirData.EnableMFA,
	}
	directories = append(directories, directory)

	app := []string{dirData.APP_ID}
	data := []map[string]interface{}{
		{
			"apps":        app,
			"directories": directories,
		},
	}
	result := map[string]interface{}{
		"data": data,
	}

	apiURL := fmt.Sprintf("%s://%s/%s/appdirectories", URL_SCHEME, ec.Host, MGMT_POP_URL)
	logging.Debug(ctx, "api URL", tags, map[string]any{"url": apiURL})

	appDirResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", result, nil, false)

	if err != nil {
		logging.Warn(ctx, "assign directories to application failed", tags, map[string]any{"error": err})
		return err
	}
	if appDirResp.StatusCode < http.StatusOK || appDirResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(appDirResp)
		logging.Warn(ctx, "assign directories to application failed", tags, map[string]any{"status": appDirResp.StatusCode})
		return logging.Wrapf(ErrAssignDirectoryFailure, tags, "%s", desc)
	}
	return nil
}

// GetIdpDirectoryGroup method searches for an IDP group within a directory
func (dirData *DirectoryData) GetIdpDirectoryGroup(ctx context.Context, ec *EaaClient, groupName string) (*GroupData, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagDirectory, logging.TagRead}
	logging.Info(ctx, "get IDP Group", tags)

	for _, group := range dirData.Groups {
		if groupName == group.Name {
			logging.Info(ctx, "group found", tags, map[string]any{"name": group.Name})
			return &group, nil
		}
	}

	return nil, logging.Errorf(tags, "group with name not found")
}

// AssignIdpDirectoryGroups assigns IDP directory groups to an application
func (dirData *DirectoryData) AssignIdpDirectoryGroups(ctx context.Context, ec *EaaClient, appUUIDURL string, appGroupsList []interface{}) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagDirectory, logging.TagAssign}
	var groups []map[string]interface{}

	for _, s := range appGroupsList {
		gData, ok := s.(map[string]interface{})
		if !ok {
			continue
		}
		appgroup := AppGroup{}
		gn, ok := gData["name"].(string)
		if !ok || gn == "" {
			continue
		}
		grp, err := dirData.GetIdpDirectoryGroup(ctx, ec, gn)
		if err != nil {
			// Fail closed: return an error when a referenced group cannot be resolved.
			// This avoids silently dropping intended assignments.
			return fmt.Errorf("group %q not found in directory %q: %w", gn, dirData.Name, err)
		}
		appgroup.UUIDURL = grp.UUID_URL

		if em, ok := gData["enable_mfa"].(string); ok {
			appgroup.EnableMFA = &em
		}

		group := map[string]interface{}{
			"uuid_url":   appgroup.UUIDURL,
			"enable_mfa": appgroup.EnableMFA,
		}
		groups = append(groups, group)
	}
	if len(groups) == 0 {
		return nil
	}
	app := []string{appUUIDURL}
	data := []map[string]interface{}{
		{
			"apps":   app,
			"groups": groups,
		},
	}
	result := map[string]interface{}{
		"data": data,
	}

	apiURL := fmt.Sprintf("%s://%s/%s/appgroups", URL_SCHEME, ec.Host, MGMT_POP_URL)
	logging.Debug(ctx, "api URL", tags, map[string]any{"url": apiURL})

	appGroupResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", result, nil, false)

	if err != nil {
		logging.Warn(ctx, "assign groups to application failed", tags, map[string]any{"error": err})
		return err
	}
	if appGroupResp.StatusCode < http.StatusOK || appGroupResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(appGroupResp)
		logging.Warn(ctx, "assign groups to application failed", tags, map[string]any{"status": appGroupResp.StatusCode})
		return logging.Errorf(tags, "assigning groups to the app failed: %s", desc)
	}
	return nil
}

// AssignAllDirectoryGroups assigns all directory groups to an application with an "inherit" enable_mfa value
func (dirData *DirectoryData) AssignAllDirectoryGroups(ctx context.Context, ec *EaaClient, appUUIDURL string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagDirectory, logging.TagAssign}
	var groups []map[string]interface{}

	for _, grp := range dirData.Groups {
		group := map[string]interface{}{
			"uuid_url":   grp.UUID_URL,
			"enable_mfa": "inherit",
		}
		groups = append(groups, group)
	}
	if len(groups) == 0 {
		return nil
	}
	app := []string{appUUIDURL}
	data := []map[string]interface{}{
		{
			"apps":   app,
			"groups": groups,
		},
	}
	result := map[string]interface{}{
		"data": data,
	}

	apiURL := fmt.Sprintf("%s://%s/%s/appgroups", URL_SCHEME, ec.Host, MGMT_POP_URL)
	logging.Debug(ctx, "api URL", tags, map[string]any{"url": apiURL})

	appGroupResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", result, nil, false)

	if err != nil {
		logging.Warn(ctx, "assign directory groups to application failed", tags, map[string]any{"error": err})
		return err
	}
	if appGroupResp.StatusCode < http.StatusOK || appGroupResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(appGroupResp)
		logging.Warn(ctx, "assign directory groups to application failed", tags, map[string]any{"status": appGroupResp.StatusCode})
		return logging.Errorf(tags, "assigning groups to the app failed: %s", desc)
	}
	return nil
}
