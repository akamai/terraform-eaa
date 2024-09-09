package client

import (
	"fmt"
	"net/http"
)

type AppIdp struct {
	App string `json:"app"`
	IDP string `json:"idp"`
}

// AssignIDP method handles the assignment of an IDP to an application.
func (ai *AppIdp) AssignIDP(ec *EaaClient) error {
	ec.Logger.Info("assigning IDP to application")
	if ai.App == "" || ai.IDP == "" {
		errMsg := fmt.Errorf("%w: app or idp is empty", ErrAssignIdpFailure)
		ec.Logger.Error("assigning IDP to Application failed. app or idp is empty")
		return errMsg
	}
	apiURL := fmt.Sprintf("%s://%s/%s/appidp", URL_SCHEME, ec.Host, MGMT_POP_URL)
	ec.Logger.Info(apiURL)

	appIdpResp, err := ec.SendAPIRequest(apiURL, "POST", ai, nil, false)
	if err != nil {
		ec.Logger.Error("assign IDP to Application failed. err", err)
		return err
	}
	if !(appIdpResp.StatusCode >= http.StatusOK && appIdpResp.StatusCode < http.StatusMultipleChoices) {
		desc, _ := FormatErrorResponse(appIdpResp)
		appIdpErrMsg := fmt.Errorf("%w: %s", ErrAssignIdpFailure, desc)
		ec.Logger.Error("assigning IDP to Application failed. appIdpResp.StatusCode", appIdpResp.StatusCode)
		return appIdpErrMsg
	}
	return nil
}

type UnAssignIDPRequest struct {
	IDP []string `json:"deleted_objects"`
}

// UnAssignIDP method handles the unassignment of an IDP to an application.
func (ai *AppIdp) UnAssignIDP(ec *EaaClient) error {
	ec.Logger.Info("unassigning IDP from application")
	if ai.App == "" || ai.IDP == "" {
		errMsg := fmt.Errorf("%w: app or idp is empty", ErrAssignIdpFailure)
		ec.Logger.Error("unassigning IDP from Application failed. app or idp is empty")
		return errMsg
	}
	var unassignIdp UnAssignIDPRequest

	apiURL := fmt.Sprintf("%s://%s/%s/appidp?method=DELETE", URL_SCHEME, ec.Host, MGMT_POP_URL)
	ec.Logger.Info(apiURL)
	unassignIdp.IDP = append(unassignIdp.IDP, ai.IDP)

	appIdpResp, err := ec.SendAPIRequest(apiURL, "POST", unassignIdp, nil, false)
	if err != nil {
		ec.Logger.Error("unassign IDP to Application failed. err", err)
		return err
	}
	if !(appIdpResp.StatusCode >= http.StatusOK && appIdpResp.StatusCode < http.StatusMultipleChoices) {
		desc, _ := FormatErrorResponse(appIdpResp)
		appIdpErrMsg := fmt.Errorf("%w: %s", ErrAssignIdpFailure, desc)
		ec.Logger.Error("unassigning IDP to Application failed. appIdpResp.StatusCode", appIdpResp.StatusCode)
		return appIdpErrMsg
	}
	return nil
}
