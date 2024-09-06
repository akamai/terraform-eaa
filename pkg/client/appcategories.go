package client

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	ErrAppCategoriesGet = errors.New("app categories get failed")
)

type AppCate struct {
	Name    string `json:"name,omitempty"`
	UUIDURL string `json:"uuid_url,omitempty"`
}

type AppCategoryResponse struct {
	Meta struct {
		Limit      int     `json:"limit,omitempty"`
		Next       *string `json:"next,omitempty"`
		Offset     int     `json:"offset,omitempty"`
		Previous   *string `json:"previous,omitempty"`
		TotalCount int     `json:"total_count,omitempty"`
	} `json:"meta,omitempty"`
	AppCategories []AppCate `json:"objects,omitempty"`
}

// GetAppCategories method retrieves app categories and formats the data as a list of maps
func GetAppCategories(ec *EaaClient) ([]AppCate, error) {
	ec.Logger.Info("GetAppCategories")
	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, APP_CATEGORIES_URL)
	acResponse := AppCategoryResponse{}

	getResp, err := ec.SendAPIRequest(apiURL, "GET", nil, &acResponse, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get app categories: %w", err)
	}
	if !(getResp.StatusCode >= http.StatusOK && getResp.StatusCode < http.StatusMultipleChoices) {
		desc, _ := FormatErrorResponse(getResp)
		appCatErrMsg := fmt.Errorf("%w: %s", ErrAppCategoriesGet, desc)
		return nil, appCatErrMsg
	}

	var acs []AppCate
	for _, ac := range acResponse.AppCategories {
		if ac.Name == "" || ac.UUIDURL == "" {
			continue
		}
		acs = append(acs, ac)
	}

	return acs, nil
}

// GetAppCategoryUuid method fetches categories and then searches for a specific category by name to return its UUID
func GetAppCategoryUuid(ec *EaaClient, categoryName string) (string, error) {
	acs, err := GetAppCategories(ec)
	if err != nil {
		return "", ErrAppCategoriesGet
	}
	for _, ac := range acs {
		if categoryName == ac.Name {
			return ac.UUIDURL, nil
		}

	}

	return "", fmt.Errorf("%w: category '%s' not found", ErrAppCategoriesGet, categoryName)
}
