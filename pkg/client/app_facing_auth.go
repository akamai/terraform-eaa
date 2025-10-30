package client

import (
    "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// shouldEnableSAMLForCreate determines if SAML should be automatically enabled during creation or update
func shouldEnableSAMLForCreate(d *schema.ResourceData, appAuth string) bool {
    appType := ""
    if at, ok := d.GetOk("app_type"); ok {
        appType = at.(string)
    }

    if appType == "saas" {
        if protocol, ok := d.GetOk("protocol"); ok {
            if protocol.(string) == "SAML" || protocol.(string) == "SAML2.0" {
                return true
            }
        }
        return false
    }

    if appAuth == "saml" || appAuth == "SAML2.0" {
        return true
    }
    if samlSettings, ok := d.GetOk("saml_settings"); ok {
        if samlList, ok := samlSettings.([]interface{}); ok && len(samlList) > 0 {
            return true
        }
    }
    return false
}

// shouldEnableOIDCForCreate determines if OIDC should be automatically enabled during creation or update
func shouldEnableOIDCForCreate(d *schema.ResourceData, appAuth string) bool {
    appType := ""
    if at, ok := d.GetOk("app_type"); ok {
        appType = at.(string)
    }

    if appType == "saas" {
        if protocol, ok := d.GetOk("protocol"); ok {
            if protocol.(string) == "OIDC" || protocol.(string) == "OpenID Connect 1.0" {
                return true
            }
        }
        return false
    }

    if appAuth == "oidc" || appAuth == "OpenID Connect 1.0" {
        return true
    }
    if oidcSettings, ok := d.GetOk("oidc_settings"); ok {
        if oidcList, ok := oidcSettings.([]interface{}); ok && len(oidcList) > 0 {
            return true
        }
    }
    return false
}

// shouldEnableWSFEDForCreate determines if WS-Federation should be automatically enabled during creation or update
func shouldEnableWSFEDForCreate(d *schema.ResourceData, appAuth string) bool {
    appType := ""
    if at, ok := d.GetOk("app_type"); ok {
        appType = at.(string)
    }

    if appType == "saas" {
        if protocol, ok := d.GetOk("protocol"); ok {
            if protocol.(string) == "WSFed" || protocol.(string) == "WS-Federation" {
                return true
            }
        }
        return false
    }

    if appAuth == "wsfed" || appAuth == "WS-Federation" {
        return true
    }
    if wsfedSettings, ok := d.GetOk("wsfed_settings"); ok {
        if wsfedList, ok := wsfedSettings.([]interface{}); ok && len(wsfedList) > 0 {
            return true
        }
    }
    return false
}

// decideAuthFromConfig centralizes auth-mode selection from schema and appAuth
// It returns which auth to enable and the normalized appAuth to send ("none" when an auth flag is used)
func decideAuthFromConfig(d *schema.ResourceData, appAuth string) (enableSAML bool, enableOIDC bool, enableWSFED bool, normalizedAppAuth string) {
    if shouldEnableSAMLForCreate(d, appAuth) {
        return true, false, false, "none"
    }
    if shouldEnableOIDCForCreate(d, appAuth) {
        return false, true, false, "none"
    }
    if shouldEnableWSFEDForCreate(d, appAuth) {
        return false, false, true, "none"
    }
    return false, false, false, appAuth
}


