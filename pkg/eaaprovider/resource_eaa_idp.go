package eaaprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	ErrIDPRollback = errors.New("IDP create rollback triggered")
)

var idpTypeNameToInt = map[string]int{
	"DEFAULT":               1,
	"EAA":                   2,
	"SAML":                  3,
	"OKTA":                  4,
	"PINGONE":               5,
	"ONELOGIN":              6,
	"GOOGLE":                7,
	"OIDC":                  8,
	"AZURE":                 9,
	"DEVICE_AUTHENTICATION": 10,
}

var idpTypeIntToName = map[int]string{
	1:  "DEFAULT",
	2:  "EAA",
	3:  "SAML",
	4:  "OKTA",
	5:  "PINGONE",
	6:  "ONELOGIN",
	7:  "GOOGLE",
	8:  "OIDC",
	9:  "AZURE",
	10: "DEVICE_AUTHENTICATION",
}

var loginDomainNameToInt = map[string]int{
	"CUSTOM":  1,
	"DEFAULT": 2,
}

var loginDomainIntToName = map[int]string{
	1: "CUSTOM",
	2: "DEFAULT",
}

func resourceEaaIdp() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceEaaIdpCreate,
		ReadContext:   resourceEaaIdpRead,
		UpdateContext: resourceEaaIdpUpdate,
		DeleteContext: resourceEaaIdpDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			// Required
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "IDP name",
			},

			// Optional typed attributes
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "IDP description",
			},
			"idp_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "IDP type: DEFAULT, EAA, SAML, OKTA, PINGONE, ONELOGIN, GOOGLE, OIDC, AZURE, DEVICE_AUTHENTICATION",
				ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
					v, ok := val.(string)
					if !ok {
						errs = append(errs, fmt.Errorf("%q must be a string", key))
						return
					}
					if _, found := idpTypeNameToInt[v]; !found {
						errs = append(errs, fmt.Errorf("%q must be one of DEFAULT, EAA, SAML, OKTA, PINGONE, ONELOGIN, GOOGLE, OIDC, AZURE, DEVICE_AUTHENTICATION; got %q", key, v))
					}
					return
				},
			},
			"login_host": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Login hostname prefix (without domain suffix)",
			},
			"login_domain": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Login domain type: CUSTOM (customer-owned domain) or DEFAULT (Akamai-managed WAPP domain)",
				ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
					v, ok := val.(string)
					if !ok {
						errs = append(errs, fmt.Errorf("%q must be a string", key))
						return
					}
					if _, found := loginDomainNameToInt[v]; !found {
						errs = append(errs, fmt.Errorf("%q must be CUSTOM or DEFAULT, got %q", key, v))
					}
					return
				},
			},
			"login_lockout": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Login lockout: \"true\" or \"off\"",
			},
			"max_login_failures": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Failed logins before lockout",
			},
			"lockout_interval": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Lockout duration in minutes",
			},
			"cookie_expiry": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Session cookie expiry in minutes",
			},
			"trust_expiry": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Trust expiry in days",
			},
			"client_principle_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Client principal name template",
			},
			"cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "TLS certificate name (resolved to uuid_url via GetCertificates)",
			},
			"client_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Client certificate name (resolved to uuid_url via GetCertificates)",
			},
			"saml_idp_custom_sign_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Custom SAML signing certificate name (resolved via GetCertificates)",
			},
			"pop": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "PoP name (resolved to uuid_url via PoPs list API)",
			},
			"failover_pop": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Failover PoP name (resolved to uuid_url via PoPs list API)",
			},
			"enable_mfa": {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Enable MFA",
			},
			"etp_enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Enable ETP integration",
			},
			"enable_access_client": {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Enable EAA Client",
			},
			"gc_client_enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Enable Global Cloud client",
			},
			"auth_request_signed": {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Sign SAML auth requests",
			},
			"auth_response_encrypt": {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Encrypt SAML auth responses",
			},
			"saml_cert_type": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "1=self-signed, 2=custom",
			},
			"saml_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "SAML URL",
			},
			"logout_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Post-logout URL",
			},
			"helpdesk_email": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Helpdesk contact email",
			},
			"default_language": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Login portal language (e.g., \"english\")",
			},
			"default_tls_suite": {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Use default TLS suite",
			},
			"custom_tls_suite_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Custom TLS suite name",
			},
			"domains": {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				Description: "Custom domains",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"agent_installation_profile": {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Enable agent install profile",
			},
			"source": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Source identifier",
			},
			"post_auth_failure_redirect_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Auth failure redirect type (EAA_APPS_PORTAL or custom)",
			},
			"post_auth_failure_redirect_custom_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Custom auth failure redirect URL",
			},
			"post_logout_redirect_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Logout redirect type (EAA_APPS_PORTAL or custom)",
			},
			"post_logout_redirect_custom_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Custom logout redirect URL",
			},

			// Optional flat maps
			"mfa_settings": {
				Type:        schema.TypeMap,
				Optional:    true,
				Computed:    true,
				Description: "MFA sub-fields (duo, pushzero, totp, sms, email, etc.)",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"settings": {
				Type:        schema.TypeMap,
				Optional:    true,
				Computed:    true,
				Description: "IDP settings (portal theme, client cert auth, IWA, force login, etc.)",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"attribute_map": {
				Type:        schema.TypeMap,
				Optional:    true,
				Computed:    true,
				Description: "SAML attribute mapping",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"multilang_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Computed:    true,
				Description: "Multi-language field overrides",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},

			// Optional list
			"directories": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Directory names to associate (resolved to uuid_url via directories list API)",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},

			// Computed read-only
			"uuid_url": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"created_at": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"modified_at": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"company_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"localization": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"status": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"dns_added": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"login_cname": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"login_dialin_server": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"login_suffix": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"domain_suffix": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"client_host": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"pop_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"idp_status": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"idp_operational": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"idp_deployed": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"directory_count": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"app_count": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"tls_suite_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

// findCertByName searches a pre-fetched certificate list for a name match.
func findCertByName(certs []client.CertObject, certName string, tags []logging.Tag) (string, error) {
	for _, cert := range certs {
		if cert.Name == certName {
			return cert.UUIDURL, nil
		}
	}
	return "", logging.Errorf(tags, "certificate with name '%s' not found", certName)
}

// findCertByUUID searches a pre-fetched certificate list for a UUID match.
func findCertByUUID(certs []client.CertObject, certUUID string) (string, bool) {
	for _, cert := range certs {
		if cert.UUIDURL == certUUID {
			return cert.Name, true
		}
	}
	return "", false
}

// findPopByName searches a pre-fetched PoP list for a name match.
func findPopByName(pops []client.Pop, popName string, tags []logging.Tag) (string, error) {
	for i := range pops {
		if pops[i].Name == popName {
			return pops[i].UUIDURL, nil
		}
	}
	return "", logging.Errorf(tags, "PoP with name '%s' not found", popName)
}

// findPopByUUID searches a pre-fetched PoP list for a UUID match.
func findPopByUUID(pops []client.Pop, popUUID string) (string, bool) {
	for i := range pops {
		if pops[i].UUIDURL == popUUID {
			return pops[i].Name, true
		}
	}
	return "", false
}

// resolveDirectoryNamesToUUIDs fetches the directory list once and resolves all names to UUIDs.
func resolveDirectoryNamesToUUIDs(ctx context.Context, ec *client.EaaClient, dirItems []interface{}, tags []logging.Tag) ([]string, error) {
	allDirs, err := client.ListDirectories(ctx, ec)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "failed to list directories for name resolution")
	}
	dirByName := make(map[string]string, len(allDirs))
	for _, d := range allDirs {
		dirByName[d.Name] = d.UUIDURL
	}

	uuids := make([]string, 0, len(dirItems))
	for _, item := range dirItems {
		name, ok := item.(string)
		if !ok {
			continue
		}
		uuid, found := dirByName[name]
		if !found {
			return nil, logging.Errorf(tags, "directory '%s' not found", name)
		}
		uuids = append(uuids, uuid)
	}
	return uuids, nil
}

// intSettingsKeys are settings keys that the API expects as integers, not strings.
var intSettingsKeys = map[string]bool{
	"idp_max_sso_sessions":          true,
	"websocket_pool_maxidle":        true,
	"websocket_pool_maxopen":        true,
	"client_cert_exp_warn_interval": true,
}

// stringMapToInterfaceMap converts map[string]interface{} from Terraform schema to a new map[string]interface{} for the API.
// Keys listed in intSettingsKeys are converted from string to integer.
func stringMapToInterfaceMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range m {
		s, ok := v.(string)
		if ok && intSettingsKeys[k] {
			if i, err := strconv.Atoi(s); err == nil {
				result[k] = i
				continue
			}
		}
		result[k] = v
	}
	return result
}

// interfaceMapToStringMap converts map[string]interface{} (API) to map[string]string (Terraform state).
func interfaceMapToStringMap(m map[string]interface{}) map[string]string {
	result := make(map[string]string)
	for k, v := range m {
		if v == nil {
			result[k] = ""
			continue
		}
		switch val := v.(type) {
		case string:
			result[k] = val
		case float64:
			if val == float64(int(val)) {
				result[k] = strconv.Itoa(int(val))
			} else {
				result[k] = strconv.FormatFloat(val, 'f', -1, 64)
			}
		case bool:
			result[k] = strconv.FormatBool(val)
		default:
			b, err := json.Marshal(val)
			if err != nil {
				result[k] = fmt.Sprintf("%v", val)
				continue
			}
			result[k] = string(b)
		}
	}
	return result
}

// rollbackIDP deletes the IDP and returns the original error wrapped with rollback context.
func rollbackIDP(ctx context.Context, d *schema.ResourceData, ec *client.EaaClient, uuid string, originalErr error, tags []logging.Tag) diag.Diagnostics {
	logging.Warn(ctx, "rolling back IDP creation", tags, map[string]any{"uuid": uuid, "error": originalErr.Error()})
	d.SetId("")
	deleteErr := client.DeleteIDP(ctx, ec, uuid)
	if deleteErr != nil {
		logging.Error(ctx, "rollback delete failed", tags, map[string]any{"delete_error": deleteErr.Error()})
		return logging.DiagFromErr(
			fmt.Errorf("%w: original error: %v, rollback delete also failed: %v", ErrIDPRollback, originalErr, deleteErr),
			tags, "IDP create failed and rollback also failed",
		)
	}
	return logging.DiagFromErr(originalErr, tags, "IDP create failed (rolled back)")
}

func ptrStringOrEmpty(p *string) string {
	if p != nil {
		return *p
	}
	return ""
}

func setStringPtr(v interface{}) *string {
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}

// setIntPtr sets an int pointer on the body from the schema value.
func setIntPtr(v interface{}) *int {
	if i, ok := v.(int); ok {
		return &i
	}
	return nil
}

// setBoolPtr sets a bool pointer on the body from the schema value.
func setBoolPtr(v interface{}) *bool {
	if b, ok := v.(bool); ok {
		return &b
	}
	return nil
}

// interfaceListToStringSlice converts []interface{} to []string safely.
func interfaceListToStringSlice(raw []interface{}) []string {
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// applyIDPConfigToBody overlays user-configured fields from the schema onto the IDP body for PUT.
func applyIDPConfigToBody(ctx context.Context, d *schema.ResourceData, ec *client.EaaClient, body *client.IDPFullResponse, tags []logging.Tag) error {
	if s, ok := d.Get("name").(string); ok {
		body.Name = s
	}

	if v, ok := d.GetOk("description"); ok {
		if s, ok := v.(string); ok {
			body.Description = s
		}
	}
	if v, ok := d.GetOk("idp_type"); ok {
		if s, ok := v.(string); ok {
			if i, found := idpTypeNameToInt[s]; found {
				body.IDPType = i
			}
		}
	}
	if d.HasChange("login_host") {
		body.LoginHost = setStringPtr(d.Get("login_host"))
	}
	if d.HasChange("login_domain") {
		if s, ok := d.Get("login_domain").(string); ok {
			if i, found := loginDomainNameToInt[s]; found {
				body.LoginDomain = &i
			}
		}
	}
	if d.HasChange("login_lockout") {
		body.LoginLockout = setStringPtr(d.Get("login_lockout"))
	}
	if d.HasChange("max_login_failures") {
		body.MaxLoginFailures = setIntPtr(d.Get("max_login_failures"))
	}
	if d.HasChange("lockout_interval") {
		body.LockoutInterval = setIntPtr(d.Get("lockout_interval"))
	}
	if d.HasChange("cookie_expiry") {
		body.CookieExpiry = setIntPtr(d.Get("cookie_expiry"))
	}
	if d.HasChange("trust_expiry") {
		body.TrustExpiry = setIntPtr(d.Get("trust_expiry"))
	}
	if d.HasChange("client_principle_name") {
		body.ClientPrincipleName = setStringPtr(d.Get("client_principle_name"))
	}

	// Resolve cert names to UUIDs (fetch cert list once for all cert fields)
	needCertLookup := d.HasChange("cert") || d.HasChange("client_cert") || d.HasChange("saml_idp_custom_sign_cert")
	var certList []client.CertObject
	if needCertLookup {
		var certErr error
		certList, certErr = client.GetCertificates(ctx, ec)
		if certErr != nil {
			return logging.Wrapf(certErr, tags, "failed to get certificates for name resolution")
		}
	}
	if d.HasChange("cert") {
		if v, ok := d.GetOk("cert"); ok {
			if certName, ok := v.(string); ok {
				certUUID, err := findCertByName(certList, certName, tags)
				if err != nil {
					return err
				}
				body.Cert = &certUUID
			}
		} else {
			empty := ""
			body.Cert = &empty
		}
	}
	if d.HasChange("client_cert") {
		if v, ok := d.GetOk("client_cert"); ok {
			if certName, ok := v.(string); ok {
				certUUID, err := findCertByName(certList, certName, tags)
				if err != nil {
					return err
				}
				body.ClientCert = &certUUID
			}
		} else {
			empty := ""
			body.ClientCert = &empty
		}
	}
	if d.HasChange("saml_idp_custom_sign_cert") {
		if v, ok := d.GetOk("saml_idp_custom_sign_cert"); ok {
			if certName, ok := v.(string); ok {
				certUUID, err := findCertByName(certList, certName, tags)
				if err != nil {
					return err
				}
				body.SAMLIDPCustomSignCert = &certUUID
			}
		} else {
			empty := ""
			body.SAMLIDPCustomSignCert = &empty
		}
	}

	// Resolve PoP names to UUIDs (fetch pop list once for both pop fields)
	needPopLookup := d.HasChange("pop") || d.HasChange("failover_pop")
	var popList []client.Pop
	if needPopLookup {
		var popErr error
		popList, popErr = client.GetPops(ctx, ec)
		if popErr != nil {
			return logging.Wrapf(popErr, tags, "failed to get pops for name resolution")
		}
	}
	if d.HasChange("pop") {
		if v, ok := d.GetOk("pop"); ok {
			if popName, ok := v.(string); ok {
				popUUID, err := findPopByName(popList, popName, tags)
				if err != nil {
					return err
				}
				body.Pop = &popUUID
			}
		} else {
			empty := ""
			body.Pop = &empty
		}
	}
	if d.HasChange("failover_pop") {
		if v, ok := d.GetOk("failover_pop"); ok {
			if popName, ok := v.(string); ok {
				popUUID, err := findPopByName(popList, popName, tags)
				if err != nil {
					return err
				}
				body.FailoverPop = &popUUID
			}
		} else {
			empty := ""
			body.FailoverPop = &empty
		}
	}

	// Boolean fields (Optional+Computed: use HasChange to allow setting false)
	if d.HasChange("enable_mfa") {
		body.EnableMFA = setBoolPtr(d.Get("enable_mfa"))
	}
	if d.HasChange("etp_enabled") {
		body.ETPEnabled = setBoolPtr(d.Get("etp_enabled"))
	}
	if d.HasChange("enable_access_client") {
		body.EnableAccessClient = setBoolPtr(d.Get("enable_access_client"))
	}
	if d.HasChange("gc_client_enabled") {
		body.GCClientEnabled = setBoolPtr(d.Get("gc_client_enabled"))
	}
	if d.HasChange("auth_request_signed") {
		body.AuthRequestSigned = setBoolPtr(d.Get("auth_request_signed"))
	}
	if d.HasChange("auth_response_encrypt") {
		body.AuthResponseEncrypt = setBoolPtr(d.Get("auth_response_encrypt"))
	}
	if d.HasChange("default_tls_suite") {
		body.DefaultTLSSuite = setBoolPtr(d.Get("default_tls_suite"))
	}
	if d.HasChange("agent_installation_profile") {
		body.AgentInstallationProfile = setBoolPtr(d.Get("agent_installation_profile"))
	}

	// Int fields (Optional+Computed: use HasChange to allow setting zero)
	if d.HasChange("saml_cert_type") {
		body.SAMLCertType = setIntPtr(d.Get("saml_cert_type"))
	}

	// String fields (Optional+Computed: use HasChange to allow setting empty)
	if d.HasChange("saml_url") {
		body.SAMLUrl = setStringPtr(d.Get("saml_url"))
	}
	if d.HasChange("logout_url") {
		body.LogoutURL = setStringPtr(d.Get("logout_url"))
	}
	if d.HasChange("helpdesk_email") {
		body.HelpdeskEmail = setStringPtr(d.Get("helpdesk_email"))
	}
	if d.HasChange("default_language") {
		body.DefaultLanguage = setStringPtr(d.Get("default_language"))
	}
	if d.HasChange("custom_tls_suite_name") {
		body.CustomTLSSuiteName = setStringPtr(d.Get("custom_tls_suite_name"))
	}
	if d.HasChange("source") {
		body.Source = setStringPtr(d.Get("source"))
	}
	if d.HasChange("post_auth_failure_redirect_type") {
		body.PostAuthFailureRedirectType = setStringPtr(d.Get("post_auth_failure_redirect_type"))
	}
	if d.HasChange("post_auth_failure_redirect_custom_url") {
		body.PostAuthFailureRedirectCustomURL = setStringPtr(d.Get("post_auth_failure_redirect_custom_url"))
	}
	if d.HasChange("post_logout_redirect_type") {
		body.PostLogoutRedirectType = setStringPtr(d.Get("post_logout_redirect_type"))
	}
	if d.HasChange("post_logout_redirect_custom_url") {
		body.PostLogoutRedirectCustomURL = setStringPtr(d.Get("post_logout_redirect_custom_url"))
	}

	// Domains list
	if v, ok := d.GetOk("domains"); ok {
		if domainsList, ok := v.([]interface{}); ok {
			body.Domains = interfaceListToStringSlice(domainsList)
		}
	}

	// Flat map fields
	if v, ok := d.GetOk("mfa_settings"); ok {
		if m, ok := v.(map[string]interface{}); ok {
			body.MFASettings = stringMapToInterfaceMap(m)
		}
	}
	if v, ok := d.GetOk("settings"); ok {
		if m, ok := v.(map[string]interface{}); ok {
			body.Settings = stringMapToInterfaceMap(m)
		}
	}
	if v, ok := d.GetOk("attribute_map"); ok {
		if m, ok := v.(map[string]interface{}); ok {
			body.AttributeMap = stringMapToInterfaceMap(m)
		}
	}
	if v, ok := d.GetOk("multilang_fields"); ok {
		if m, ok := v.(map[string]interface{}); ok {
			body.MultilangFields = stringMapToInterfaceMap(m)
		}
	}

	return nil
}

// resourceEaaIdpCreate creates a new EAA IDP with rollback on failure.
func resourceEaaIdpCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagIDP, logging.TagCreate}
	logging.Info(ctx, "creating IDP", tags)

	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	// Step 1: POST to create the IDP with minimal fields
	createReq := &client.IDPCreateRequest{}
	if s, ok := d.Get("name").(string); ok {
		createReq.Name = s
	}
	if v, ok := d.GetOk("description"); ok {
		if s, ok := v.(string); ok {
			createReq.Description = s
		}
	}
	if v, ok := d.GetOk("idp_type"); ok {
		if s, ok := v.(string); ok {
			if i, found := idpTypeNameToInt[s]; found {
				createReq.IDPType = i
			}
		}
	}

	createResp, err := client.CreateIDP(ctx, eaaclient, createReq)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to create IDP")
	}

	idpUUID := createResp.UUIDURL
	d.SetId(idpUUID)

	// From here on, any failure triggers rollback
	// Step 2: GET current state, overlay user config, PUT
	currentIDP, err := client.GetIDP(ctx, eaaclient, idpUUID)
	if err != nil {
		return rollbackIDP(ctx, d, eaaclient, idpUUID, err, tags)
	}

	if applyErr := applyIDPConfigToBody(ctx, d, eaaclient, currentIDP, tags); applyErr != nil {
		return rollbackIDP(ctx, d, eaaclient, idpUUID, applyErr, tags)
	}

	_, err = client.UpdateIDP(ctx, eaaclient, idpUUID, currentIDP)
	if err != nil {
		return rollbackIDP(ctx, d, eaaclient, idpUUID, err, tags)
	}

	// Step 3: Associate directories if configured
	if v, ok := d.GetOk("directories"); ok {
		dirSet, ok := v.(*schema.Set)
		if !ok {
			return logging.DiagFromErr(fmt.Errorf("directories is not a *schema.Set"), tags, "unexpected type for directories")
		}
		dirList := dirSet.List()
		if len(dirList) > 0 {
			dirUUIDs, dirErr := resolveDirectoryNamesToUUIDs(ctx, eaaclient, dirList, tags)
			if dirErr != nil {
				return rollbackIDP(ctx, d, eaaclient, idpUUID, dirErr, tags)
			}
			if assocErr := client.AssociateDirectoriesToIDP(ctx, eaaclient, idpUUID, dirUUIDs); assocErr != nil {
				return rollbackIDP(ctx, d, eaaclient, idpUUID, assocErr, tags)
			}
		}
	}

	// Step 4: Deploy
	if deployErr := client.DeployIDP(ctx, eaaclient, idpUUID); deployErr != nil {
		return rollbackIDP(ctx, d, eaaclient, idpUUID, deployErr, tags)
	}

	logging.Info(ctx, "IDP created successfully", tags, map[string]any{"uuid": idpUUID})
	return resourceEaaIdpRead(ctx, d, m)
}

// resourceEaaIdpRead reads an existing EAA IDP and populates the Terraform state.
func resourceEaaIdpRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagIDP, logging.TagRead}
	logging.Info(ctx, "reading IDP", tags)

	id := d.Id()
	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	// Step 1: GET IDP
	idpResp, err := client.GetIDP(ctx, eaaclient, id)
	if err != nil {
		if errors.Is(err, client.ErrIDPNotFound) {
			logging.Warn(ctx, "IDP not found, removing from state", tags, map[string]any{"uuid": id})
			d.SetId("")
			return nil
		}
		return logging.DiagFromErr(err, tags, "failed to read IDP")
	}

	// Step 2: GET directory memberships
	memberships, err := client.GetIDPDirectoryMemberships(ctx, eaaclient, id)
	if err != nil {
		logging.Warn(ctx, "failed to get IDP directory memberships", tags, map[string]any{"error": err.Error()})
	}

	// Build attrs map
	attrs := make(map[string]interface{})
	attrs["name"] = idpResp.Name
	attrs["uuid_url"] = idpResp.UUIDURL
	attrs["description"] = idpResp.Description
	if name, ok := idpTypeIntToName[idpResp.IDPType]; ok {
		attrs["idp_type"] = name
	} else {
		attrs["idp_type"] = strconv.Itoa(idpResp.IDPType)
	}
	attrs["created_at"] = idpResp.CreatedAt
	attrs["modified_at"] = idpResp.ModifiedAt
	attrs["company_id"] = idpResp.CompanyID
	attrs["localization"] = idpResp.Localization
	attrs["status"] = idpResp.Status
	attrs["dns_added"] = idpResp.DNSAdded
	attrs["login_cname"] = idpResp.LoginCName
	attrs["login_dialin_server"] = idpResp.LoginDialinServer
	attrs["login_suffix"] = idpResp.LoginSuffix
	attrs["domain_suffix"] = idpResp.DomainSuffix
	attrs["client_host"] = idpResp.ClientHost
	attrs["pop_name"] = idpResp.PopName
	attrs["idp_status"] = idpResp.IDPStatus
	attrs["idp_operational"] = idpResp.IDPOperational
	attrs["idp_deployed"] = idpResp.IDPDeployed
	attrs["directory_count"] = idpResp.DirectoryCount
	attrs["app_count"] = idpResp.AppCount
	attrs["tls_suite_name"] = idpResp.TLSSuiteName

	// Optional string pointer fields — use "" when nil to clear stale state
	attrs["login_host"] = ptrStringOrEmpty(idpResp.LoginHost)
	attrs["login_lockout"] = ptrStringOrEmpty(idpResp.LoginLockout)
	attrs["client_principle_name"] = ptrStringOrEmpty(idpResp.ClientPrincipleName)
	attrs["saml_url"] = ptrStringOrEmpty(idpResp.SAMLUrl)
	attrs["logout_url"] = ptrStringOrEmpty(idpResp.LogoutURL)
	attrs["helpdesk_email"] = ptrStringOrEmpty(idpResp.HelpdeskEmail)
	attrs["default_language"] = ptrStringOrEmpty(idpResp.DefaultLanguage)
	attrs["custom_tls_suite_name"] = ptrStringOrEmpty(idpResp.CustomTLSSuiteName)
	attrs["source"] = ptrStringOrEmpty(idpResp.Source)
	attrs["post_auth_failure_redirect_type"] = ptrStringOrEmpty(idpResp.PostAuthFailureRedirectType)
	attrs["post_auth_failure_redirect_custom_url"] = ptrStringOrEmpty(idpResp.PostAuthFailureRedirectCustomURL)
	attrs["post_logout_redirect_type"] = ptrStringOrEmpty(idpResp.PostLogoutRedirectType)
	attrs["post_logout_redirect_custom_url"] = ptrStringOrEmpty(idpResp.PostLogoutRedirectCustomURL)

	// Optional int pointer fields — use 0 when nil
	if idpResp.LoginDomain != nil {
		if name, ok := loginDomainIntToName[*idpResp.LoginDomain]; ok {
			attrs["login_domain"] = name
		} else {
			attrs["login_domain"] = strconv.Itoa(*idpResp.LoginDomain)
		}
	} else {
		attrs["login_domain"] = ""
	}
	if idpResp.MaxLoginFailures != nil {
		attrs["max_login_failures"] = *idpResp.MaxLoginFailures
	} else {
		attrs["max_login_failures"] = 0
	}
	if idpResp.LockoutInterval != nil {
		attrs["lockout_interval"] = *idpResp.LockoutInterval
	} else {
		attrs["lockout_interval"] = 0
	}
	if idpResp.CookieExpiry != nil {
		attrs["cookie_expiry"] = *idpResp.CookieExpiry
	} else {
		attrs["cookie_expiry"] = 0
	}
	if idpResp.TrustExpiry != nil {
		attrs["trust_expiry"] = *idpResp.TrustExpiry
	} else {
		attrs["trust_expiry"] = 0
	}
	if idpResp.SAMLCertType != nil {
		attrs["saml_cert_type"] = *idpResp.SAMLCertType
	} else {
		attrs["saml_cert_type"] = 0
	}

	// Optional bool pointer fields — use false when nil
	if idpResp.EnableMFA != nil {
		attrs["enable_mfa"] = *idpResp.EnableMFA
	} else {
		attrs["enable_mfa"] = false
	}
	if idpResp.ETPEnabled != nil {
		attrs["etp_enabled"] = *idpResp.ETPEnabled
	} else {
		attrs["etp_enabled"] = false
	}
	if idpResp.EnableAccessClient != nil {
		attrs["enable_access_client"] = *idpResp.EnableAccessClient
	} else {
		attrs["enable_access_client"] = false
	}
	if idpResp.GCClientEnabled != nil {
		attrs["gc_client_enabled"] = *idpResp.GCClientEnabled
	} else {
		attrs["gc_client_enabled"] = false
	}
	if idpResp.AuthRequestSigned != nil {
		attrs["auth_request_signed"] = *idpResp.AuthRequestSigned
	} else {
		attrs["auth_request_signed"] = false
	}
	if idpResp.AuthResponseEncrypt != nil {
		attrs["auth_response_encrypt"] = *idpResp.AuthResponseEncrypt
	} else {
		attrs["auth_response_encrypt"] = false
	}
	if idpResp.DefaultTLSSuite != nil {
		attrs["default_tls_suite"] = *idpResp.DefaultTLSSuite
	} else {
		attrs["default_tls_suite"] = false
	}
	if idpResp.AgentInstallationProfile != nil {
		attrs["agent_installation_profile"] = *idpResp.AgentInstallationProfile
	} else {
		attrs["agent_installation_profile"] = false
	}

	// Reverse-resolve cert UUIDs to names (fetch cert list once)
	hasCertFields := (idpResp.Cert != nil && *idpResp.Cert != "") ||
		(idpResp.ClientCert != nil && *idpResp.ClientCert != "") ||
		(idpResp.SAMLIDPCustomSignCert != nil && *idpResp.SAMLIDPCustomSignCert != "")
	var readCerts []client.CertObject
	if hasCertFields {
		var certErr error
		readCerts, certErr = client.GetCertificates(ctx, eaaclient)
		if certErr != nil {
			logging.Warn(ctx, "failed to get certificates for UUID resolution", tags, map[string]any{"error": certErr.Error()})
		}
	}

	attrs["cert"] = ""
	if idpResp.Cert != nil && *idpResp.Cert != "" {
		if name, ok := findCertByUUID(readCerts, *idpResp.Cert); ok {
			attrs["cert"] = name
		} else {
			logging.Warn(ctx, "failed to resolve cert UUID to name", tags, map[string]any{"uuid": *idpResp.Cert})
		}
	}
	attrs["client_cert"] = ""
	if idpResp.ClientCert != nil && *idpResp.ClientCert != "" {
		if name, ok := findCertByUUID(readCerts, *idpResp.ClientCert); ok {
			attrs["client_cert"] = name
		} else {
			logging.Warn(ctx, "failed to resolve client_cert UUID to name", tags, map[string]any{"uuid": *idpResp.ClientCert})
		}
	}
	attrs["saml_idp_custom_sign_cert"] = ""
	if idpResp.SAMLIDPCustomSignCert != nil && *idpResp.SAMLIDPCustomSignCert != "" {
		if name, ok := findCertByUUID(readCerts, *idpResp.SAMLIDPCustomSignCert); ok {
			attrs["saml_idp_custom_sign_cert"] = name
		} else {
			logging.Warn(ctx, "failed to resolve saml_idp_custom_sign_cert UUID to name", tags, map[string]any{"uuid": *idpResp.SAMLIDPCustomSignCert})
		}
	}

	// Reverse-resolve PoP UUIDs to names (fetch pop list once)
	hasPopFields := (idpResp.Pop != nil && *idpResp.Pop != "") ||
		(idpResp.FailoverPop != nil && *idpResp.FailoverPop != "")
	var readPops []client.Pop
	if hasPopFields {
		var popErr error
		readPops, popErr = client.GetPops(ctx, eaaclient)
		if popErr != nil {
			logging.Warn(ctx, "failed to get pops for UUID resolution", tags, map[string]any{"error": popErr.Error()})
		}
	}

	attrs["pop"] = ""
	if idpResp.Pop != nil && *idpResp.Pop != "" {
		if name, ok := findPopByUUID(readPops, *idpResp.Pop); ok {
			attrs["pop"] = name
		} else {
			logging.Warn(ctx, "failed to resolve pop UUID to name", tags, map[string]any{"uuid": *idpResp.Pop})
		}
	}
	attrs["failover_pop"] = ""
	if idpResp.FailoverPop != nil && *idpResp.FailoverPop != "" {
		if name, ok := findPopByUUID(readPops, *idpResp.FailoverPop); ok {
			attrs["failover_pop"] = name
		} else {
			logging.Warn(ctx, "failed to resolve failover_pop UUID to name", tags, map[string]any{"uuid": *idpResp.FailoverPop})
		}
	}

	if err := client.SetAttrs(d, attrs); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set IDP attributes")
	}

	// Set domains list separately (SetAttrs doesn't handle lists well)
	// Always set domains, even if empty, to clear stale state
	domains := idpResp.Domains
	if domains == nil {
		domains = []string{}
	}
	if err := d.Set("domains", domains); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set domains")
	}

	// Set flat map fields — always set even when nil to keep state consistent
	mfaSettings := map[string]string{}
	if idpResp.MFASettings != nil {
		mfaSettings = interfaceMapToStringMap(idpResp.MFASettings)
	}
	if err := d.Set("mfa_settings", mfaSettings); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set mfa_settings")
	}

	settingsMap := map[string]string{}
	if idpResp.Settings != nil {
		settingsMap = interfaceMapToStringMap(idpResp.Settings)
	}
	if err := d.Set("settings", settingsMap); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set settings")
	}

	attrMap := map[string]string{}
	if idpResp.AttributeMap != nil {
		attrMap = interfaceMapToStringMap(idpResp.AttributeMap)
	}
	if err := d.Set("attribute_map", attrMap); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set attribute_map")
	}

	multilangMap := map[string]string{}
	if idpResp.MultilangFields != nil {
		multilangMap = interfaceMapToStringMap(idpResp.MultilangFields)
	}
	if err := d.Set("multilang_fields", multilangMap); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set multilang_fields")
	}

	// Set directories from memberships (names, not UUIDs)
	// Always set directories, even if empty, to clear stale state
	dirNames := make([]string, 0, len(memberships))
	for _, membership := range memberships {
		if membership.Directory.Name != "" {
			dirNames = append(dirNames, membership.Directory.Name)
		}
	}
	if err := d.Set("directories", dirNames); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set directories")
	}

	logging.Info(ctx, "IDP read successfully", tags)
	return nil
}

// resourceEaaIdpUpdate updates an existing EAA IDP.
func resourceEaaIdpUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagIDP, logging.TagUpdate}
	logging.Info(ctx, "updating IDP", tags)

	id := d.Id()
	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	// Step 1: GET current IDP state
	currentIDP, err := client.GetIDP(ctx, eaaclient, id)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to read IDP for update")
	}

	// Step 2: Overlay user config onto current state
	if applyErr := applyIDPConfigToBody(ctx, d, eaaclient, currentIDP, tags); applyErr != nil {
		return logging.DiagFromErr(applyErr, tags, "failed to resolve IDP config for update")
	}

	// Step 3: PUT updated IDP
	_, err = client.UpdateIDP(ctx, eaaclient, id, currentIDP)
	if err != nil {
		// Read back actual API state so Terraform doesn't keep the rejected values
		readDiags := resourceEaaIdpRead(ctx, d, m)
		updateDiags := logging.DiagFromErr(err, tags, "failed to update IDP")
		return append(updateDiags, readDiags...)
	}

	// Step 4: Diff directories
	if d.HasChange("directories") {
		oldRaw, newRaw := d.GetChange("directories")
		oldSet, ok := oldRaw.(*schema.Set)
		if !ok {
			return logging.DiagFromErr(fmt.Errorf("old directories is not a *schema.Set"), tags, "unexpected type for directories")
		}
		newSet, ok := newRaw.(*schema.Set)
		if !ok {
			return logging.DiagFromErr(fmt.Errorf("new directories is not a *schema.Set"), tags, "unexpected type for directories")
		}

		removed := oldSet.Difference(newSet)
		added := newSet.Difference(oldSet)

		// Directories to remove (in old but not in new)
		var toRemoveNames []string
		for _, v := range removed.List() {
			if name, ok := v.(string); ok {
				toRemoveNames = append(toRemoveNames, name)
			}
		}

		// Directories to add (in new but not in old)
		var toAddNames []string
		for _, v := range added.List() {
			if name, ok := v.(string); ok {
				toAddNames = append(toAddNames, name)
			}
		}

		// Disassociate removed directories using membership UUIDs
		if len(toRemoveNames) > 0 {
			dirMemberships, memberErr := client.GetIDPDirectoryMemberships(ctx, eaaclient, id)
			if memberErr != nil {
				return logging.DiagFromErr(memberErr, tags, "failed to get memberships for directory diff")
			}

			removeSet := make(map[string]bool, len(toRemoveNames))
			for _, name := range toRemoveNames {
				removeSet[name] = true
			}

			var membershipUUIDs []string
			for _, membership := range dirMemberships {
				if removeSet[membership.Directory.Name] {
					membershipUUIDs = append(membershipUUIDs, membership.UUIDURL)
				}
			}

			if len(membershipUUIDs) > 0 {
				if disassocErr := client.DisassociateDirectoriesFromIDP(ctx, eaaclient, membershipUUIDs); disassocErr != nil {
					return logging.DiagFromErr(disassocErr, tags, "failed to disassociate directories")
				}
			}
		}

		// Associate added directories
		if len(toAddNames) > 0 {
			addItems := make([]interface{}, len(toAddNames))
			for i, name := range toAddNames {
				addItems[i] = name
			}
			dirUUIDs, dirErr := resolveDirectoryNamesToUUIDs(ctx, eaaclient, addItems, tags)
			if dirErr != nil {
				return logging.DiagFromErr(dirErr, tags, "failed to resolve directory names")
			}
			if assocErr := client.AssociateDirectoriesToIDP(ctx, eaaclient, id, dirUUIDs); assocErr != nil {
				return logging.DiagFromErr(assocErr, tags, "failed to associate directories")
			}
		}
	}

	// Step 5: Deploy
	if deployErr := client.DeployIDP(ctx, eaaclient, id); deployErr != nil {
		return logging.DiagFromErr(deployErr, tags, "failed to deploy IDP after update")
	}

	logging.Info(ctx, "IDP updated successfully", tags)
	return resourceEaaIdpRead(ctx, d, m)
}

// resourceEaaIdpDelete deletes an existing EAA IDP, disassociating directories first.
func resourceEaaIdpDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagIDP, logging.TagDelete}
	logging.Info(ctx, "deleting IDP", tags)

	id := d.Id()
	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	// Step 1: Disassociate all directories first
	memberships, err := client.GetIDPDirectoryMemberships(ctx, eaaclient, id)
	if err != nil {
		logging.Warn(ctx, "failed to get memberships for delete, continuing", tags, map[string]any{"error": err.Error()})
	} else if len(memberships) > 0 {
		membershipUUIDs := make([]string, 0, len(memberships))
		for _, membership := range memberships {
			membershipUUIDs = append(membershipUUIDs, membership.UUIDURL)
		}
		if disassocErr := client.DisassociateDirectoriesFromIDP(ctx, eaaclient, membershipUUIDs); disassocErr != nil {
			return logging.DiagFromErr(disassocErr, tags, "failed to disassociate directories before delete")
		}
	}

	// Step 2: Delete the IDP
	err = client.DeleteIDP(ctx, eaaclient, id)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to delete IDP")
	}

	// Step 3: Clear the ID
	d.SetId("")

	logging.Info(ctx, "IDP deleted successfully", tags)
	return nil
}
