package eaaprovider

import (
	"context"
	"errors"
	"fmt"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	ErrIDPRollback = errors.New("IDP create rollback triggered")
)

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
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "IDP type (e.g., 2 = certificate-based)",
			},
			"login_host": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Login hostname prefix (without domain suffix)",
			},
			"login_domain": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Login domain type (2 = WAPP)",
			},
			"login_lockout": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Login lockout: \"true\" or \"off\"",
			},
			"max_login_failures": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Failed logins before lockout",
			},
			"lockout_interval": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Lockout duration in minutes",
			},
			"cookie_expiry": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Session cookie expiry in minutes",
			},
			"trust_expiry": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Trust expiry in days",
			},
			"client_principle_name": {
				Type:        schema.TypeString,
				Optional:    true,
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
				Description: "Enable MFA",
			},
			"etp_enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable ETP integration",
			},
			"enable_access_client": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable EAA Client",
			},
			"gc_client_enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable Global Cloud client",
			},
			"auth_request_signed": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Sign SAML auth requests",
			},
			"auth_response_encrypt": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Encrypt SAML auth responses",
			},
			"saml_cert_type": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "1=self-signed, 2=custom",
			},
			"saml_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "SAML URL",
			},
			"logout_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Post-logout URL",
			},
			"helpdesk_email": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Helpdesk contact email",
			},
			"default_language": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Login portal language (e.g., \"english\")",
			},
			"default_tls_suite": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Use default TLS suite",
			},
			"custom_tls_suite_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Custom TLS suite name",
			},
			"domains": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Custom domains",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"agent_installation_profile": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable agent install profile",
			},
			"source": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Source identifier",
			},
			"post_auth_failure_redirect_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Auth failure redirect type (EAA_APPS_PORTAL or custom)",
			},
			"post_auth_failure_redirect_custom_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Custom auth failure redirect URL",
			},
			"post_logout_redirect_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Logout redirect type (EAA_APPS_PORTAL or custom)",
			},
			"post_logout_redirect_custom_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Custom logout redirect URL",
			},

			// Optional flat maps
			"mfa_settings": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "MFA sub-fields (duo, pushzero, totp, sms, email, etc.)",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"settings": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "IDP settings (portal theme, client cert auth, IWA, force login, etc.)",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"attribute_map": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "SAML attribute mapping",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"multilang_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Multi-language field overrides",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},

			// Optional list
			"directories": {
				Type:        schema.TypeList,
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

// resolveCertNameToUUID resolves a certificate name to its uuid_url by searching the certificates list.
func resolveCertNameToUUID(ctx context.Context, ec *client.EaaClient, certName string, tags []logging.Tag) (string, error) {
	certs, err := client.GetCertificates(ctx, ec)
	if err != nil {
		return "", logging.Wrapf(err, tags, "failed to get certificates for name resolution")
	}
	for _, cert := range certs {
		if cert.Name == certName {
			return cert.UUIDURL, nil
		}
	}
	return "", logging.Errorf(tags, "certificate with name '%s' not found", certName)
}

// resolveCertUUIDToName resolves a certificate uuid_url back to its name.
func resolveCertUUIDToName(ctx context.Context, ec *client.EaaClient, certUUID string, tags []logging.Tag) (string, error) {
	certs, err := client.GetCertificates(ctx, ec)
	if err != nil {
		return "", logging.Wrapf(err, tags, "failed to get certificates for UUID resolution")
	}
	for _, cert := range certs {
		if cert.UUIDURL == certUUID {
			return cert.Name, nil
		}
	}
	return "", logging.Errorf(tags, "certificate with UUID '%s' not found", certUUID)
}

// resolvePopUUIDToName resolves a PoP uuid_url back to its name.
func resolvePopUUIDToName(ctx context.Context, ec *client.EaaClient, popUUID string, tags []logging.Tag) (string, error) {
	pops, err := client.GetPops(ctx, ec)
	if err != nil {
		return "", logging.Wrapf(err, tags, "failed to get pops for UUID resolution")
	}
	for i := range pops {
		if pops[i].UUIDURL == popUUID {
			return pops[i].Name, nil
		}
	}
	return "", logging.Errorf(tags, "PoP with UUID '%s' not found", popUUID)
}

// stringMapToInterfaceMap converts map[string]interface{} from Terraform schema to a new map[string]interface{} for the API.
func stringMapToInterfaceMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range m {
		result[k] = v
	}
	return result
}

// interfaceMapToStringMap converts map[string]interface{} (API) to map[string]string (Terraform state).
func interfaceMapToStringMap(m map[string]interface{}) map[string]string {
	result := make(map[string]string)
	for k, v := range m {
		result[k] = fmt.Sprintf("%v", v)
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

// setStringPtr sets a string pointer on the body from the schema value.
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
		if i, ok := v.(int); ok {
			body.IDPType = i
		}
	}
	if v, ok := d.GetOk("login_host"); ok {
		body.LoginHost = setStringPtr(v)
	}
	if v, ok := d.GetOk("login_domain"); ok {
		body.LoginDomain = setIntPtr(v)
	}
	if v, ok := d.GetOk("login_lockout"); ok {
		body.LoginLockout = setStringPtr(v)
	}
	if v, ok := d.GetOk("max_login_failures"); ok {
		body.MaxLoginFailures = setIntPtr(v)
	}
	if v, ok := d.GetOk("lockout_interval"); ok {
		body.LockoutInterval = setIntPtr(v)
	}
	if v, ok := d.GetOk("cookie_expiry"); ok {
		body.CookieExpiry = setIntPtr(v)
	}
	if v, ok := d.GetOk("trust_expiry"); ok {
		body.TrustExpiry = setIntPtr(v)
	}
	if v, ok := d.GetOk("client_principle_name"); ok {
		body.ClientPrincipleName = setStringPtr(v)
	}

	// Resolve cert names to UUIDs
	if v, ok := d.GetOk("cert"); ok {
		if certName, ok := v.(string); ok {
			certUUID, err := resolveCertNameToUUID(ctx, ec, certName, tags)
			if err != nil {
				return err
			}
			body.Cert = &certUUID
		}
	}
	if v, ok := d.GetOk("client_cert"); ok {
		if certName, ok := v.(string); ok {
			certUUID, err := resolveCertNameToUUID(ctx, ec, certName, tags)
			if err != nil {
				return err
			}
			body.ClientCert = &certUUID
		}
	}
	if v, ok := d.GetOk("saml_idp_custom_sign_cert"); ok {
		if certName, ok := v.(string); ok {
			certUUID, err := resolveCertNameToUUID(ctx, ec, certName, tags)
			if err != nil {
				return err
			}
			body.SAMLIDPCustomSignCert = &certUUID
		}
	}

	// Resolve PoP names to UUIDs
	if v, ok := d.GetOk("pop"); ok {
		if popName, ok := v.(string); ok {
			pop, err := client.GetPopByName(ctx, ec, popName)
			if err != nil {
				return err
			}
			body.Pop = &pop.UUIDURL
		}
	}
	if v, ok := d.GetOk("failover_pop"); ok {
		if popName, ok := v.(string); ok {
			pop, err := client.GetPopByName(ctx, ec, popName)
			if err != nil {
				return err
			}
			body.FailoverPop = &pop.UUIDURL
		}
	}

	// Boolean fields
	if v, ok := d.GetOk("enable_mfa"); ok {
		body.EnableMFA = setBoolPtr(v)
	}
	if v, ok := d.GetOk("etp_enabled"); ok {
		body.ETPEnabled = setBoolPtr(v)
	}
	if v, ok := d.GetOk("enable_access_client"); ok {
		body.EnableAccessClient = setBoolPtr(v)
	}
	if v, ok := d.GetOk("gc_client_enabled"); ok {
		body.GCClientEnabled = setBoolPtr(v)
	}
	if v, ok := d.GetOk("auth_request_signed"); ok {
		body.AuthRequestSigned = setBoolPtr(v)
	}
	if v, ok := d.GetOk("auth_response_encrypt"); ok {
		body.AuthResponseEncrypt = setBoolPtr(v)
	}
	if v, ok := d.GetOk("default_tls_suite"); ok {
		body.DefaultTLSSuite = setBoolPtr(v)
	}
	if v, ok := d.GetOk("agent_installation_profile"); ok {
		body.AgentInstallationProfile = setBoolPtr(v)
	}

	// Int fields
	if v, ok := d.GetOk("saml_cert_type"); ok {
		body.SAMLCertType = setIntPtr(v)
	}

	// String fields
	if v, ok := d.GetOk("saml_url"); ok {
		body.SAMLUrl = setStringPtr(v)
	}
	if v, ok := d.GetOk("logout_url"); ok {
		body.LogoutURL = setStringPtr(v)
	}
	if v, ok := d.GetOk("helpdesk_email"); ok {
		body.HelpdeskEmail = setStringPtr(v)
	}
	if v, ok := d.GetOk("default_language"); ok {
		body.DefaultLanguage = setStringPtr(v)
	}
	if v, ok := d.GetOk("custom_tls_suite_name"); ok {
		body.CustomTLSSuiteName = setStringPtr(v)
	}
	if v, ok := d.GetOk("source"); ok {
		body.Source = setStringPtr(v)
	}
	if v, ok := d.GetOk("post_auth_failure_redirect_type"); ok {
		body.PostAuthFailureRedirectType = setStringPtr(v)
	}
	if v, ok := d.GetOk("post_auth_failure_redirect_custom_url"); ok {
		body.PostAuthFailureRedirectCustomURL = setStringPtr(v)
	}
	if v, ok := d.GetOk("post_logout_redirect_type"); ok {
		body.PostLogoutRedirectType = setStringPtr(v)
	}
	if v, ok := d.GetOk("post_logout_redirect_custom_url"); ok {
		body.PostLogoutRedirectCustomURL = setStringPtr(v)
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
		if i, ok := v.(int); ok {
			createReq.IDPType = i
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
		if dirList, ok := v.([]interface{}); ok {
			dirUUIDs := make([]string, 0, len(dirList))
			for _, dn := range dirList {
				if dirName, ok := dn.(string); ok {
					dirEntry, dirErr := client.GetDirectoryByName(ctx, eaaclient, dirName)
					if dirErr != nil {
						return rollbackIDP(ctx, d, eaaclient, idpUUID, dirErr, tags)
					}
					dirUUIDs = append(dirUUIDs, dirEntry.UUIDURL)
				}
			}
			if len(dirUUIDs) > 0 {
				if assocErr := client.AssociateDirectoriesToIDP(ctx, eaaclient, idpUUID, dirUUIDs); assocErr != nil {
					return rollbackIDP(ctx, d, eaaclient, idpUUID, assocErr, tags)
				}
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
		// Non-fatal: continue without directory info
	}

	// Build attrs map
	attrs := make(map[string]interface{})
	attrs["name"] = idpResp.Name
	attrs["uuid_url"] = idpResp.UUIDURL
	attrs["description"] = idpResp.Description
	attrs["idp_type"] = idpResp.IDPType
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

	// Optional pointer fields
	if idpResp.LoginHost != nil {
		attrs["login_host"] = *idpResp.LoginHost
	}
	if idpResp.LoginDomain != nil {
		attrs["login_domain"] = *idpResp.LoginDomain
	}
	if idpResp.LoginLockout != nil {
		attrs["login_lockout"] = *idpResp.LoginLockout
	}
	if idpResp.MaxLoginFailures != nil {
		attrs["max_login_failures"] = *idpResp.MaxLoginFailures
	}
	if idpResp.LockoutInterval != nil {
		attrs["lockout_interval"] = *idpResp.LockoutInterval
	}
	if idpResp.CookieExpiry != nil {
		attrs["cookie_expiry"] = *idpResp.CookieExpiry
	}
	if idpResp.TrustExpiry != nil {
		attrs["trust_expiry"] = *idpResp.TrustExpiry
	}
	if idpResp.ClientPrincipleName != nil {
		attrs["client_principle_name"] = *idpResp.ClientPrincipleName
	}
	if idpResp.EnableMFA != nil {
		attrs["enable_mfa"] = *idpResp.EnableMFA
	}
	if idpResp.ETPEnabled != nil {
		attrs["etp_enabled"] = *idpResp.ETPEnabled
	}
	if idpResp.EnableAccessClient != nil {
		attrs["enable_access_client"] = *idpResp.EnableAccessClient
	}
	if idpResp.GCClientEnabled != nil {
		attrs["gc_client_enabled"] = *idpResp.GCClientEnabled
	}
	if idpResp.AuthRequestSigned != nil {
		attrs["auth_request_signed"] = *idpResp.AuthRequestSigned
	}
	if idpResp.AuthResponseEncrypt != nil {
		attrs["auth_response_encrypt"] = *idpResp.AuthResponseEncrypt
	}
	if idpResp.SAMLCertType != nil {
		attrs["saml_cert_type"] = *idpResp.SAMLCertType
	}
	if idpResp.SAMLUrl != nil {
		attrs["saml_url"] = *idpResp.SAMLUrl
	}
	if idpResp.LogoutURL != nil {
		attrs["logout_url"] = *idpResp.LogoutURL
	}
	if idpResp.HelpdeskEmail != nil {
		attrs["helpdesk_email"] = *idpResp.HelpdeskEmail
	}
	if idpResp.DefaultLanguage != nil {
		attrs["default_language"] = *idpResp.DefaultLanguage
	}
	if idpResp.DefaultTLSSuite != nil {
		attrs["default_tls_suite"] = *idpResp.DefaultTLSSuite
	}
	if idpResp.CustomTLSSuiteName != nil {
		attrs["custom_tls_suite_name"] = *idpResp.CustomTLSSuiteName
	}
	if idpResp.AgentInstallationProfile != nil {
		attrs["agent_installation_profile"] = *idpResp.AgentInstallationProfile
	}
	if idpResp.Source != nil {
		attrs["source"] = *idpResp.Source
	}
	if idpResp.PostAuthFailureRedirectType != nil {
		attrs["post_auth_failure_redirect_type"] = *idpResp.PostAuthFailureRedirectType
	}
	if idpResp.PostAuthFailureRedirectCustomURL != nil {
		attrs["post_auth_failure_redirect_custom_url"] = *idpResp.PostAuthFailureRedirectCustomURL
	}
	if idpResp.PostLogoutRedirectType != nil {
		attrs["post_logout_redirect_type"] = *idpResp.PostLogoutRedirectType
	}
	if idpResp.PostLogoutRedirectCustomURL != nil {
		attrs["post_logout_redirect_custom_url"] = *idpResp.PostLogoutRedirectCustomURL
	}

	// Reverse-resolve cert UUIDs to names
	if idpResp.Cert != nil && *idpResp.Cert != "" {
		certName, certErr := resolveCertUUIDToName(ctx, eaaclient, *idpResp.Cert, tags)
		if certErr != nil {
			logging.Warn(ctx, "failed to resolve cert UUID to name", tags, map[string]any{"uuid": *idpResp.Cert, "error": certErr.Error()})
		} else {
			attrs["cert"] = certName
		}
	}
	if idpResp.ClientCert != nil && *idpResp.ClientCert != "" {
		certName, certErr := resolveCertUUIDToName(ctx, eaaclient, *idpResp.ClientCert, tags)
		if certErr != nil {
			logging.Warn(ctx, "failed to resolve client_cert UUID to name", tags, map[string]any{"uuid": *idpResp.ClientCert, "error": certErr.Error()})
		} else {
			attrs["client_cert"] = certName
		}
	}
	if idpResp.SAMLIDPCustomSignCert != nil && *idpResp.SAMLIDPCustomSignCert != "" {
		certName, certErr := resolveCertUUIDToName(ctx, eaaclient, *idpResp.SAMLIDPCustomSignCert, tags)
		if certErr != nil {
			logging.Warn(ctx, "failed to resolve saml_idp_custom_sign_cert UUID to name", tags, map[string]any{"uuid": *idpResp.SAMLIDPCustomSignCert, "error": certErr.Error()})
		} else {
			attrs["saml_idp_custom_sign_cert"] = certName
		}
	}

	// Reverse-resolve PoP UUIDs to names
	if idpResp.Pop != nil && *idpResp.Pop != "" {
		popName, popErr := resolvePopUUIDToName(ctx, eaaclient, *idpResp.Pop, tags)
		if popErr != nil {
			logging.Warn(ctx, "failed to resolve pop UUID to name", tags, map[string]any{"uuid": *idpResp.Pop, "error": popErr.Error()})
		} else {
			attrs["pop"] = popName
		}
	}
	if idpResp.FailoverPop != nil && *idpResp.FailoverPop != "" {
		popName, popErr := resolvePopUUIDToName(ctx, eaaclient, *idpResp.FailoverPop, tags)
		if popErr != nil {
			logging.Warn(ctx, "failed to resolve failover_pop UUID to name", tags, map[string]any{"uuid": *idpResp.FailoverPop, "error": popErr.Error()})
		} else {
			attrs["failover_pop"] = popName
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

	// Set flat map fields
	if idpResp.MFASettings != nil {
		if err := d.Set("mfa_settings", interfaceMapToStringMap(idpResp.MFASettings)); err != nil {
			return logging.DiagFromErr(err, tags, "failed to set mfa_settings")
		}
	}
	if idpResp.Settings != nil {
		if err := d.Set("settings", interfaceMapToStringMap(idpResp.Settings)); err != nil {
			return logging.DiagFromErr(err, tags, "failed to set settings")
		}
	}
	if idpResp.AttributeMap != nil {
		if err := d.Set("attribute_map", interfaceMapToStringMap(idpResp.AttributeMap)); err != nil {
			return logging.DiagFromErr(err, tags, "failed to set attribute_map")
		}
	}
	if idpResp.MultilangFields != nil {
		if err := d.Set("multilang_fields", interfaceMapToStringMap(idpResp.MultilangFields)); err != nil {
			return logging.DiagFromErr(err, tags, "failed to set multilang_fields")
		}
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
		return logging.DiagFromErr(err, tags, "failed to update IDP")
	}

	// Step 4: Diff directories
	if d.HasChange("directories") {
		oldRaw, newRaw := d.GetChange("directories")
		var oldDirs []interface{}
		var newDirs []interface{}
		if od, ok := oldRaw.([]interface{}); ok {
			oldDirs = od
		}
		if nd, ok := newRaw.([]interface{}); ok {
			newDirs = nd
		}

		oldSet := make(map[string]bool, len(oldDirs))
		for _, od := range oldDirs {
			if s, ok := od.(string); ok {
				oldSet[s] = true
			}
		}
		newSet := make(map[string]bool, len(newDirs))
		for _, nd := range newDirs {
			if s, ok := nd.(string); ok {
				newSet[s] = true
			}
		}

		// Directories to remove (in old but not in new)
		var toRemoveNames []string
		for _, od := range oldDirs {
			if name, ok := od.(string); ok && !newSet[name] {
				toRemoveNames = append(toRemoveNames, name)
			}
		}

		// Directories to add (in new but not in old)
		var toAddNames []string
		for _, nd := range newDirs {
			if name, ok := nd.(string); ok && !oldSet[name] {
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
			dirUUIDs := make([]string, 0, len(toAddNames))
			for _, name := range toAddNames {
				dirEntry, dirErr := client.GetDirectoryByName(ctx, eaaclient, name)
				if dirErr != nil {
					return logging.DiagFromErr(dirErr, tags, fmt.Sprintf("failed to resolve directory '%s'", name))
				}
				dirUUIDs = append(dirUUIDs, dirEntry.UUIDURL)
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
