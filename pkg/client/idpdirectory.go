package client

import (
	"context"
	"fmt"
	"net/http"

	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
)

type IDPDirRef struct {
	UUIDURL string `json:"directory_uuid_url,omitempty"`
	Name    string `json:"name,omitempty"`
}

type IDPRef struct {
	UUIDURL string `json:"idp_uuid_url,omitempty"`
	Name    string `json:"name,omitempty"`
}

type IDPDirectoryMembership struct {
	UUIDURL   string    `json:"uuid_url"`
	Directory IDPDirRef `json:"directory"`
	IDP       IDPRef    `json:"idp"`
}

type IDPDirectoryMembershipResponse struct {
	Objects []IDPDirectoryMembership `json:"objects"`
	Meta    Meta                     `json:"meta,omitempty"`
}

type idpDirAssociateRequest struct {
	IDP         string   `json:"idp"`
	Directories []string `json:"directories"`
}

type idpDirDisassociateRequest struct {
	DeletedObjects []string `json:"deleted_objects"`
}

func GetIDPDirectoryMemberships(ctx context.Context, ec *EaaClient, idpUUID string) ([]IDPDirectoryMembership, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagIDP, logging.TagDirectory, logging.TagList}
	logging.Info(ctx, "getting IDP directory memberships", tags, map[string]any{"idp_uuid": idpUUID})

	apiURL := fmt.Sprintf("%s://%s/%s/%s/directories_membership", URL_SCHEME, ec.Host, IDP_URL, idpUUID)

	noExpand := false
	var resp IDPDirectoryMembershipResponse
	httpResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &resp, false, GetRequestOptions{Expand: &noExpand})
	if err != nil {
		return nil, logging.Wrapf(err, tags, "get IDP directory memberships failed")
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(httpResp)
		return nil, logging.Errorf(tags, "get IDP directory memberships failed: %s", desc)
	}

	return resp.Objects, nil
}

func AssociateDirectoriesToIDP(ctx context.Context, ec *EaaClient, idpUUID string, dirUUIDs []string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagIDP, logging.TagDirectory, logging.TagAssign}
	if len(dirUUIDs) == 0 {
		return nil
	}
	logging.Info(ctx, "associating directories to IDP", tags, map[string]any{"idp_uuid": idpUUID, "count": len(dirUUIDs)})

	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, IDPDIRECTORY_URL)
	req := idpDirAssociateRequest{
		IDP:         idpUUID,
		Directories: dirUUIDs,
	}

	httpResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", &req, nil, false)
	if err != nil {
		return logging.Wrapf(err, tags, "associate directories to IDP failed")
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(httpResp)
		return logging.Wrapf(ErrIDPDirectoryAssociate, tags, "HTTP %d: %s", httpResp.StatusCode, desc)
	}

	logging.Info(ctx, "directories associated to IDP", tags)
	return nil
}

func DisassociateDirectoriesFromIDP(ctx context.Context, ec *EaaClient, membershipUUIDs []string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagIDP, logging.TagDirectory, logging.TagDelete}
	if len(membershipUUIDs) == 0 {
		return nil
	}
	logging.Info(ctx, "disassociating directories from IDP", tags, map[string]any{"count": len(membershipUUIDs)})

	apiURL := fmt.Sprintf("%s://%s/%s?method=DELETE", URL_SCHEME, ec.Host, IDPDIRECTORY_URL)
	req := idpDirDisassociateRequest{
		DeletedObjects: membershipUUIDs,
	}

	httpResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", &req, nil, false)
	if err != nil {
		return logging.Wrapf(err, tags, "disassociate directories from IDP failed")
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(httpResp)
		return logging.Wrapf(ErrIDPDirectoryDisassociate, tags, "HTTP %d: %s", httpResp.StatusCode, desc)
	}

	logging.Info(ctx, "directories disassociated from IDP", tags)
	return nil
}
