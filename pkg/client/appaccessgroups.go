package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

var (
	ErrAppAccessGroupsGet = errors.New("app access groups get failed")
)

// AppAccessGroup represents an app access group
type AppAccessGroup struct {
	UUID        string `json:"uuid,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	IsEnabled   bool   `json:"is_enabled,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
	ModifiedAt  string `json:"modified_at,omitempty"`
	ResourceURI struct {
		Href string `json:"href,omitempty"`
	} `json:"resource_uri,omitempty"`
}

// AppAccessGroupsResponse represents the response from the app access groups API
type AppAccessGroupsResponse struct {
	Meta struct {
		Limit      int     `json:"limit"`
		Next       *string `json:"next"`
		Offset     int     `json:"offset"`
		Previous   *string `json:"previous"`
		TotalCount int     `json:"total_count"`
	} `json:"meta"`
	Objects []AppAccessGroup `json:"objects"`
}

// GetAppAccessGroups retrieves app access groups for a connector pool
func GetAppAccessGroups(ctx context.Context, ec *EaaClient, connectorPoolUUID, contractID, gid string, limit, offset int, order, sortBy string) ([]AppAccessGroup, error) {
	apiURL := fmt.Sprintf("%s://%s/%s?connector_pool_uuid_url=%s&contractId=%s&limit=%d&offset=%d&order=%s&sort_by=%s",
		URL_SCHEME, ec.Host, APP_ACCESS_GROUPS_URL, connectorPoolUUID, contractID, limit, offset, order, sortBy)

	ec.Logger.Info("Getting app access groups with URL:", apiURL)

	var response AppAccessGroupsResponse
	resp, err := ec.SendAPIRequest(apiURL, "GET", nil, &response, false)
	if err != nil {
		ec.Logger.Error("Get app access groups API request failed:", err)
		return nil, err
	}

	ec.Logger.Info("Get app access groups response status:", resp.StatusCode)
	ec.Logger.Info("Get app access groups response body:", response)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		desc, _ := FormatErrorResponse(resp)
		getErrMsg := fmt.Errorf("%w: %s", ErrAppAccessGroupsGet, desc)
		ec.Logger.Error("Get app access groups failed with status:", resp.StatusCode, "error:", desc)
		return nil, getErrMsg
	}

	return response.Objects, nil
}
