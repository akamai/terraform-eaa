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
	AppCategories []AppCate `json:"objects,omitempty"`
	Meta          struct {
		Next       *string `json:"next,omitempty"`
		Previous   *string `json:"previous,omitempty"`
		Limit      int     `json:"limit,omitempty"`
		Offset     int     `json:"offset,omitempty"`
		TotalCount int     `json:"total_count,omitempty"`
	} `json:"meta,omitempty"`
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
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(getResp)
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

// GetAppCategoryUUID fetches categories and returns the UUID for the requested category name.
func GetAppCategoryUUID(ec *EaaClient, categoryName string) (string, error) {
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
