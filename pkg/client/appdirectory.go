package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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
	APP_ID    string `json:"app_id,omitempty"`
	UUID      string `json:"uuid_url,omitempty"`
	EnableMFA *bool  `json:"enable_mfa,omitempty"`
}

type AppGroup struct {
	UUIDURL   string  `json:"uuid_url,omitempty"`
	EnableMFA *string `json:"enable_mfa,omitempty"`
}

// AssignIdpDirectory method assigns an IDP directory to an application.
func (dirData *AppDirectory) AssignIdpDirectory(ctx context.Context, ec *EaaClient) error {
	ec.Logger.Info("assign IDP directory")
	if dirData.APP_ID == "" || dirData.UUID == "" {
		assignErrMsg := fmt.Errorf("%w: app or dir is empty", ErrAssignDirectoryFailure)
		ec.Logger.Error("assign directories to application failed. app or dir is empty")
		return assignErrMsg
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
	ec.Logger.Info(apiURL)

	appDirResp, err := ec.SendAPIRequest(apiURL, "POST", result, nil, false)

	if err != nil {
		ec.Logger.Error("assign directories to application failed. err", err)
		return err
	}
	if !(appDirResp.StatusCode >= http.StatusOK && appDirResp.StatusCode < http.StatusMultipleChoices) {
		desc, _ := FormatErrorResponse(appDirResp)
		assignDirErrMsg := fmt.Errorf("%w: %s", ErrAssignDirectoryFailure, desc)
		ec.Logger.Error("assign directories to application failed. appDirResp.StatusCode", appDirResp.StatusCode)
		return assignDirErrMsg
	}
	return nil
}

// GetIdpDirectoryGroup method searches for an IDP group within a directory
func (dirData *DirectoryData) GetIdpDirectoryGroup(ctx context.Context, ec *EaaClient, groupName string) (*GroupData, error) {
	ec.Logger.Info("get IDP Group ")
	for _, group := range dirData.Groups {
		if groupName == group.Name {
			ec.Logger.Info(group.Name)
			return &group, nil
		}
	}

	return nil, errors.New("group with name not found")
}

// AssignIdpDirectoryGroups assigns IDP directory groups to an application
func (dirData *DirectoryData) AssignIdpDirectoryGroups(ctx context.Context, ec *EaaClient, app_uuid_url string, appGroupsList []interface{}) error {
	var groups []map[string]interface{}

	for _, s := range appGroupsList {
		if gData, ok := s.(map[string]interface{}); ok {
			appgroup := AppGroup{}
			gn, ok := gData["name"].(string)
			if !ok || gn == "" {
				continue
			}
			grp, err := dirData.GetIdpDirectoryGroup(ctx, ec, gn)
			if err != nil {
				continue
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
	}
	if len(groups) == 0 {
		return nil
	}
	app := []string{app_uuid_url}
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
	ec.Logger.Info(apiURL)

	appGroupResp, err := ec.SendAPIRequest(apiURL, "POST", result, nil, false)

	if err != nil {
		ec.Logger.Error("assign groups to application failed. err", err)
		return err
	}
	if !(appGroupResp.StatusCode >= http.StatusOK && appGroupResp.StatusCode < http.StatusMultipleChoices) {
		desc, _ := FormatErrorResponse(appGroupResp)
		assignGrpErrMsg := fmt.Errorf("%w: %s", ErrAssignGroupFailure, desc)
		ec.Logger.Error("assign groups to application failed. appGroupResp.StatusCode: ", appGroupResp.StatusCode)
		return assignGrpErrMsg
	}
	return nil
}

// AssignAllDirectoryGroups assigns all directory groups to an application with an "inherit" enable_mfa value
func (dirData *DirectoryData) AssignAllDirectoryGroups(ctx context.Context, ec *EaaClient, app_uuid_url string) error {
	var groups []map[string]interface{}

	for _, grp := range dirData.Groups {
		appgroup := AppGroup{}
		appgroup.UUIDURL = grp.UUID_URL
		group := map[string]interface{}{
			"uuid_url":   grp.UUID_URL,
			"enable_mfa": "inherit",
		}
		groups = append(groups, group)
	}
	if len(groups) == 0 {
		return nil
	}
	app := []string{app_uuid_url}
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
	ec.Logger.Info(apiURL)

	appGroupResp, err := ec.SendAPIRequest(apiURL, "POST", result, nil, false)

	if err != nil {
		ec.Logger.Error("assign directory groups to application failed. err", err)
		return err
	}
	if !(appGroupResp.StatusCode >= http.StatusOK && appGroupResp.StatusCode < http.StatusMultipleChoices) {
		desc, _ := FormatErrorResponse(appGroupResp)
		appGroupErrMsg := fmt.Errorf("%w: %s", ErrAssignGroupFailure, desc)
		ec.Logger.Error("assign directory groups to application failed. appGroupResp.StatusCode: ", appGroupResp.StatusCode)
		return appGroupErrMsg
	}
	return nil
}
