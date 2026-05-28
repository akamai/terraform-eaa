package client

import (
	"context"
	"fmt"
	"net/http"

	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
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
func GetAppCategories(ctx context.Context, ec *EaaClient) ([]AppCate, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagList}
	logging.Info(ctx, "GetAppCategories", tags)

	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, APP_CATEGORIES_URL)
	acResponse := AppCategoryResponse{}

	getResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &acResponse, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "failed to get app categories")
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(getResp)
		return nil, logging.Errorf(tags, "app categories get failed: %s", desc)
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
func GetAppCategoryUUID(ctx context.Context, ec *EaaClient, categoryName string) (string, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagRead}
	acs, err := GetAppCategories(ctx, ec)
	if err != nil {
		return "", logging.Errorf(tags, "app categories get failed")
	}
	for _, ac := range acs {
		if categoryName == ac.Name {
			return ac.UUIDURL, nil
		}

	}

	return "", logging.Errorf(tags, "app categories get failed: category '%s' not found", categoryName)
}
