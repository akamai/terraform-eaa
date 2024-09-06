package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

var (
	ErrIDPGet            = errors.New("idps get failed")
	ErrIDPDirectoriesGet = errors.New("idp directories get failed")
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
	Meta Meta              `json:"meta,omitempty"`
	IDPS []IDPResponseData `json:"objects,omitempty"`
}

type DirectoryResponse struct {
	Meta          Meta            `json:"meta,omitempty"`
	DirectoryList []DirectoryData `json:"objects,omitempty"`
}

type Meta struct {
	Limit      int     `json:"limit,omitempty"`
	Next       *string `json:"next,omitempty"`
	Offset     int     `json:"offset,omitempty"`
	Previous   *string `json:"previous,omitempty"`
	TotalCount int     `json:"total_count,omitempty"`
}

func GetIDPS(ctx context.Context, ec *EaaClient) (*IDPList, error) {
	ec.Logger.Info("getIDPs call")

	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, IDP_URL)
	ec.Logger.Info(apiURL)

	idpResponse := IDPResponse{}
	getResp, err := ec.SendAPIRequest(apiURL, "GET", nil, &idpResponse, false)
	if err != nil {
		return nil, err
	}
	if !(getResp.StatusCode >= http.StatusOK && getResp.StatusCode < http.StatusMultipleChoices) {
		desc, _ := FormatErrorResponse(getResp)
		getIdpErrMsg := fmt.Errorf("%w: %s", ErrIDPGet, desc)
		return nil, getIdpErrMsg
	}

	idpList := IDPList{}
	idps := []IDPData{}
	for _, idp := range idpResponse.IDPS {
		if idp.Name == "" || idp.UUIDURL == "" {
			continue
		}
		directoryList, err := GetIDPDirectories(ec, idp.UUIDURL)
		if err != nil {
			return nil, ErrIDPGet
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
	ec.Logger.Info("GetIdpWithName ", idpName)
	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, IDP_URL)
	ec.Logger.Info(apiURL)

	idpResponse := IDPResponse{}
	getResp, err := ec.SendAPIRequest(apiURL, "GET", nil, &idpResponse, false)
	if err != nil {
		return nil, err
	}
	if !(getResp.StatusCode >= http.StatusOK && getResp.StatusCode < http.StatusMultipleChoices) {
		desc, _ := FormatErrorResponse(getResp)
		getIdpErrMsg := fmt.Errorf("%w: %s", ErrIDPGet, desc)
		return nil, getIdpErrMsg
	}

	for _, idp := range idpResponse.IDPS {
		if idp.Name == idpName {
			directoryList, err := GetIDPDirectories(ec, idp.UUIDURL)
			if err != nil {
				return nil, (ErrIDPGet)
			}
			idpData := IDPData{
				Name:        idp.Name,
				UUIDURL:     idp.UUIDURL,
				Directories: directoryList,
			}
			return &idpData, nil
		}
	}

	return nil, errors.New("IDP with name not found")
}

func (idpData *IDPData) GetIdpDirectory(ctx context.Context, ec *EaaClient, dirName string) (*DirectoryData, error) {

	for _, directory := range idpData.Directories {
		if dirName == directory.Name {
			ec.Logger.Info(directory.Name)
			return &directory, nil
		}
	}

	return nil, errors.New("IDP with name not found")
}

func GetIDPDirectories(ec *EaaClient, idpUUID string) ([]DirectoryData, error) {
	apiURL := fmt.Sprintf("%s://%s/%s/%s/directories", URL_SCHEME, ec.Host, IDP_URL, idpUUID)
	ec.Logger.Info("getIDPDirectories for idpUUID ", idpUUID)
	ec.Logger.Info(apiURL)
	directoryResponse := DirectoryResponse{}

	getResp, err := ec.SendAPIRequest(apiURL, "GET", nil, &directoryResponse, false)
	if err != nil {
		return nil, err
	}
	if !(getResp.StatusCode >= http.StatusOK && getResp.StatusCode < http.StatusMultipleChoices) {
		desc, _ := FormatErrorResponse(getResp)
		getIdpDirsErrMsg := fmt.Errorf("%w: %s", ErrIDPDirectoriesGet, desc)
		return nil, getIdpDirsErrMsg
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

func (idpData *IDPData) AssignIdpDirectories(ctx context.Context, appDirs interface{}, app_uuid_url string, ec *EaaClient) error {
	ec.Logger.Info("assigning directories to application")
	if appDirsList, ok := appDirs.([]interface{}); ok {
		for _, s := range appDirsList {
			if sData, ok := s.(map[string]interface{}); ok {
				appdir := AppDirectory{}
				if dirName, ok := sData["name"].(string); ok {
					ec.Logger.Info(dirName)
					if em, ok := sData["enable_mfa"].(bool); ok {
						appdir.EnableMFA = &em
					}
					dirData, err := idpData.GetIdpDirectory(ctx, ec, dirName)
					if err != nil {
						ec.Logger.Info("directory with name does not exist")
						continue
					}
					appdir.UUID = dirData.UUID
					appdir.APP_ID = app_uuid_url
					err = appdir.AssignIdpDirectory(ctx, ec)
					if err != nil {
						ec.Logger.Info("directory assignment failed")
						return err
					}

					if appGroupsList, ok := sData["app_groups"].([]interface{}); ok {
						if len(appGroupsList) > 0 {
							err = dirData.AssignIdpDirectoryGroups(ctx, ec, app_uuid_url, appGroupsList)
						} else {
							err = dirData.AssignAllDirectoryGroups(ctx, ec, app_uuid_url)
						}
						if err != nil {
							ec.Logger.Info("directory groups assignment failed")
							return err
						}
					}
				}
			}
		}
	}
	return nil
}
