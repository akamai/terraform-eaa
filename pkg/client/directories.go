package client

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
)

type DirectoryListEntry struct {
	Name          string `json:"name"`
	UUIDURL       string `json:"uuid_url"`
	Service       int    `json:"service"`
	Status        int    `json:"status"`
	DirectoryType int    `json:"directory_type"`
	UserCount     int    `json:"user_count"`
	GroupCount    int    `json:"group_count"`
}

type DirectoryListResponse struct {
	Objects []DirectoryListEntry `json:"objects"`
	Meta    Meta                 `json:"meta,omitempty"`
}

func ListDirectories(ctx context.Context, ec *EaaClient) ([]DirectoryListEntry, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagDirectory, logging.TagList}
	logging.Info(ctx, "listing directories", tags)

	var dirs []DirectoryListEntry
	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, DIRECTORIES_URL)

	for apiURL != "" {
		var resp DirectoryListResponse
		httpResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &resp, false)
		if err != nil {
			return nil, logging.Wrapf(err, tags, "list directories API request failed")
		}
		if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
			desc := FormatErrorDescription(httpResp)
			return nil, logging.Errorf(tags, "list directories failed: %s", desc)
		}

		for _, d := range resp.Objects {
			if d.Name == "" || d.UUIDURL == "" {
				continue
			}
			dirs = append(dirs, d)
		}

		if resp.Meta.Next != nil {
			nextURL := strings.TrimPrefix(*resp.Meta.Next, "/api/v1")
			apiURL = fmt.Sprintf("%s://%s/%s%s", URL_SCHEME, ec.Host, MGMT_POP_URL, nextURL)
		} else {
			apiURL = ""
		}
	}

	return dirs, nil
}

func GetDirectoryByName(ctx context.Context, ec *EaaClient, name string) (*DirectoryListEntry, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagDirectory, logging.TagRead}
	logging.Info(ctx, "getting directory by name", tags, map[string]any{"name": name})

	dirs, err := ListDirectories(ctx, ec)
	if err != nil {
		return nil, err
	}
	for i := range dirs {
		if dirs[i].Name == name {
			return &dirs[i], nil
		}
	}
	return nil, logging.Wrapf(ErrDirectoryNotFound, tags, "directory '%s' not found", name)
}
