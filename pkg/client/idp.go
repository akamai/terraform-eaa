package client

import (
	"context"
	"fmt"
	"net/http"

	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
)

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
			return nil, logging.Errorf(tags, "idps get failed")
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
				return nil, logging.Errorf(tags, "idps get failed")
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
						logging.Info(ctx, "directory with name does not exist", tags)
						continue
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
