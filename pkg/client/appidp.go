package client

import (
	"context"
	"fmt"
	"net/http"

	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
)

type AppIdp struct {
	App string `json:"app"`
	IDP string `json:"idp"`
}

// AssignIDP method handles the assignment of an IDP to an application.
func (ai *AppIdp) AssignIDP(ctx context.Context, ec *EaaClient) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagIDP, logging.TagAssign}
	logging.Info(ctx, "assigning IDP to application", tags)

	if ai.App == "" || ai.IDP == "" {
		logging.Warn(ctx, "assigning IDP to Application failed: app or idp is empty", tags)
		return logging.Wrapf(ErrAssignIdpFailure, tags, "app or idp is empty")
	}
	apiURL := fmt.Sprintf("%s://%s/%s/appidp", URL_SCHEME, ec.Host, MGMT_POP_URL)
	logging.Debug(ctx, "api URL", tags, map[string]any{"url": apiURL})

	appIdpResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", ai, nil, false)
	if err != nil {
		logging.Warn(ctx, "assign IDP to Application failed", tags, map[string]any{"error": err})
		return err
	}
	if appIdpResp.StatusCode < http.StatusOK || appIdpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(appIdpResp)
		logging.Warn(ctx, "assigning IDP to Application failed", tags, map[string]any{"status": appIdpResp.StatusCode})
		return logging.Wrapf(ErrAssignIdpFailure, tags, "%s", desc)
	}
	return nil
}

type UnAssignIDPRequest struct {
	IDP []string `json:"deleted_objects"`
}

// UnAssignIDP method handles the unassignment of an IDP to an application.
func (ai *AppIdp) UnAssignIDP(ctx context.Context, ec *EaaClient) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagIDP, logging.TagAssign}
	logging.Info(ctx, "unassigning IDP from application", tags)

	if ai.App == "" || ai.IDP == "" {
		logging.Warn(ctx, "unassigning IDP from Application failed: app or idp is empty", tags)
		return logging.Wrapf(ErrAssignIdpFailure, tags, "app or idp is empty")
	}
	var unassignIdp UnAssignIDPRequest

	apiURL := fmt.Sprintf("%s://%s/%s/appidp?method=DELETE", URL_SCHEME, ec.Host, MGMT_POP_URL)
	logging.Debug(ctx, "api URL", tags, map[string]any{"url": apiURL})
	unassignIdp.IDP = append(unassignIdp.IDP, ai.IDP)

	appIdpResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", unassignIdp, nil, false)
	if err != nil {
		logging.Warn(ctx, "unassign IDP from Application failed", tags, map[string]any{"error": err})
		return err
	}
	if appIdpResp.StatusCode < http.StatusOK || appIdpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(appIdpResp)
		logging.Warn(ctx, "unassigning IDP from Application failed", tags, map[string]any{"status": appIdpResp.StatusCode})
		return logging.Wrapf(ErrAssignIdpFailure, tags, "%s", desc)
	}
	return nil
}
