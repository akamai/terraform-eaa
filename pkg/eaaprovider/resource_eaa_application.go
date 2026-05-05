package eaaprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	ErrGetApp      = errors.New("app get failed")
	ErrInvalidData = errors.New("invalid data in schema")
)

func getAppError(resp *http.Response) error {
	desc := client.FormatErrorDescription(resp)
	if desc == "" || desc == "unknown error" {
		return client.ErrGetAppFailed
	}

	return fmt.Errorf("%w: %s", client.ErrGetAppFailed, desc)
}

func resourceEaaApplication() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceEaaApplicationCreateTwoPhase,
		ReadContext:   resourceEaaApplicationRead,
		UpdateContext: resourceEaaApplicationUpdate,
		DeleteContext: resourceEaaApplicationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"app_profile": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"app_type": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"protocol": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Authentication protocol for SaaS applications. Valid values: SAML, SAML2.0, OIDC, OpenID Connect 1.0, WSFed, WS-Federation",
				ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
					v, ok := val.(string)
					if !ok {
						errs = append(errs, fmt.Errorf("%q must be a string", key))
						return
					}
					validProtocols := []string{"SAML", "SAML2.0", "OIDC", "OpenID Connect 1.0", "WSFed", "WS-Federation"}
					isValid := false
					for _, protocol := range validProtocols {
						if v == protocol {
							isValid = true
							break
						}
					}
					if !isValid {
						errs = append(errs, fmt.Errorf("%q must be one of: %v", key, validProtocols))
					}
					return
				},
			},
			"client_app_mode": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"host": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"bookmark_url": {
				Type:     schema.TypeString,
				Optional: true,
			},

			"domain": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"domain_suffix": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"origin_host": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"orig_tls": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"origin_port": {
				Type:     schema.TypeInt,
				Optional: true,
			},
			"tunnel_internal_hosts": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"host": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"port_range": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"proto_type": {
							Type:     schema.TypeInt,
							Optional: true,
						},
					},
				},
			},
			"servers": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"origin_host": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"orig_tls": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"origin_port": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"origin_protocol": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"pop": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"popname": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"popregion": {
				Type:     schema.TypeString,
				Optional: true,
			},

			"auth_enabled": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "false",
			},
			"saml": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Automatically set to true when SAML authentication is configured. This field is computed based on app_auth in advanced_settings and cannot be set directly.",
			},
			"saml_settings": {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				MaxItems:    1,
				Description: "SAML configuration settings using nested blocks",
				DefaultFunc: func() (interface{}, error) {
					return []interface{}{}, nil
				},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"sp": {
							Type:        schema.TypeList,
							Optional:    true,
							MaxItems:    1,
							Description: "SAML Service Provider configuration",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"entity_id": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "SAML SP Entity ID",
									},
									"acs_url": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "SAML SP Assertion Consumer Service URL",
									},
									"slo_url": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "SAML SP Single Logout URL",
									},
									"dst_url": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "SAML SP Destination URL",
									},
									"resp_bind": {
										Type:         schema.TypeString,
										Optional:     true,
										Default:      string(client.DefaultSAMLResponseBinding),
										Description:  "SAML SP Response Binding",
										ValidateFunc: validateSAMLResponseBinding,
									},
									"token_life": {
										Type:        schema.TypeInt,
										Optional:    true,
										Default:     client.DefaultSAMLTokenLife,
										Description: "SAML SP Token Lifetime (seconds)",
									},
									"encr_algo": {
										Type:         schema.TypeString,
										Optional:     true,
										Default:      string(client.DefaultSAMLEncryptionAlgorithm),
										Description:  "SAML SP Encryption Algorithm",
										ValidateFunc: validateSAMLEncryptionAlgorithm,
									},
								},
							},
						},
						"idp": {
							Type:        schema.TypeList,
							Optional:    true,
							MaxItems:    1,
							Description: "SAML Identity Provider configuration",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"entity_id": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "SAML IDP Entity ID",
									},
									"sign_algo": {
										Type:         schema.TypeString,
										Optional:     true,
										Default:      string(client.DefaultSAMLSigningAlgorithm),
										Description:  "SAML IDP Signing Algorithm",
										ValidateFunc: validateSAMLSigningAlgorithm,
									},
									"sign_cert": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "SAML IDP Signing Certificate (required when self_signed = false)",
									},
									"sign_key": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "SAML IDP Signing Key (optional)",
									},
									"self_signed": {
										Type:        schema.TypeBool,
										Optional:    true,
										Default:     true,
										Description: "Whether the SAML IDP uses self-signed certificates",
									},
								},
							},
						},
						"subject": {
							Type:        schema.TypeList,
							Optional:    true,
							MaxItems:    1,
							Description: "SAML Subject configuration",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"fmt": {
										Type:         schema.TypeString,
										Optional:     true,
										Default:      string(client.DefaultSAMLSubjectFormat),
										Description:  "SAML Subject format",
										ValidateFunc: validateSAMLSubjectFormat,
									},
									"src": {
										Type:        schema.TypeString,
										Optional:    true,
										Default:     client.DefaultSAMLSubjectSource,
										Description: "SAML Subject source",
									},
								},
							},
						},
						"attrmap": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "SAML Attribute mapping configuration",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:        schema.TypeString,
										Required:    true,
										Description: "SAML Attribute name",
									},
									"fname": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "SAML Attribute friendly name",
									},
									"fmt": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "SAML Attribute format",
									},
									"val": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "SAML Attribute value",
									},
									"src": {
										Type:        schema.TypeString,
										Required:    true,
										Description: "SAML Attribute source",
									},
									"rule": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "SAML Attribute rule",
									},
								},
							},
						},
					},
				},
			},
			"wsfed": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Automatically set to true when WS-Federation authentication is configured. This field is computed based on app_auth in advanced_settings and cannot be set directly.",
			},
			"wsfed_settings": {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				MaxItems:    1,
				Description: "WS-Federation configuration settings",
				DefaultFunc: func() (interface{}, error) {
					return []interface{}{}, nil
				},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"sp": {
							Type:        schema.TypeList,
							Optional:    true,
							MaxItems:    1,
							Description: "WS-Federation Service Provider configuration",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"entity_id": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "WS-Federation SP Entity ID",
									},
									"slo_url": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "WS-Federation SP Single Logout URL",
									},
									"dst_url": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "WS-Federation SP Destination URL",
									},
									"resp_bind": {
										Type:        schema.TypeString,
										Optional:    true,
										Default:     "post",
										Description: "WS-Federation SP Response Binding",
									},
									"token_life": {
										Type:        schema.TypeInt,
										Optional:    true,
										Default:     3600,
										Description: "WS-Federation SP Token Lifetime (seconds)",
									},
									"encr_algo": {
										Type:        schema.TypeString,
										Optional:    true,
										Default:     "aes256-cbc",
										Description: "WS-Federation SP Encryption Algorithm",
									},
								},
							},
						},
						"idp": {
							Type:        schema.TypeList,
							Optional:    true,
							MaxItems:    1,
							Description: "WS-Federation Identity Provider configuration",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"entity_id": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "WS-Federation IDP Entity ID",
									},
									"sign_algo": {
										Type:        schema.TypeString,
										Optional:    true,
										Default:     "SHA256",
										Description: "WS-Federation IDP Signing Algorithm",
									},
									"sign_cert": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "WS-Federation IDP Signing Certificate (required when self_signed = false)",
									},
									"sign_key": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "WS-Federation IDP Signing Key (required when self_signed = false)",
									},
									"self_signed": {
										Type:        schema.TypeBool,
										Optional:    true,
										Default:     true,
										Description: "Whether the WS-Federation IDP uses self-signed certificates",
									},
								},
							},
						},
						"subject": {
							Type:        schema.TypeList,
							Optional:    true,
							MaxItems:    1,
							Description: "WS-Federation Subject configuration",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"fmt": {
										Type:        schema.TypeString,
										Optional:    true,
										Default:     "email",
										Description: "WS-Federation Subject Name ID Format",
									},
									"custom_fmt": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "WS-Federation Subject Custom Format",
									},
									"src": {
										Type:        schema.TypeString,
										Optional:    true,
										Default:     "user.email",
										Description: "WS-Federation Subject Source Attribute",
									},
									"val": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "WS-Federation Subject Value",
									},
									"rule": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "WS-Federation Subject Rule",
									},
								},
							},
						},
						"attrmap": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "WS-Federation Attribute mapping",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "Attribute name",
									},
									"fmt": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "Attribute format",
									},
									"custom_fmt": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "Attribute custom format",
									},
									"val": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "Attribute value",
									},
									"src": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "Attribute source",
									},
									"rule": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "Attribute rule",
									},
								},
							},
						},
					},
				},
			},

			"oidc": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Automatically set to true when OIDC authentication is configured. This field is computed based on app_auth in advanced_settings and cannot be set directly.",
			},
			"oidc_settings": {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				MaxItems:    1,
				Description: "OpenID Connect configuration settings using nested blocks",
				DefaultFunc: func() (interface{}, error) {
					return []interface{}{}, nil
				},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"authorization_endpoint": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "OIDC Authorization Endpoint URL",
						},
						"token_endpoint": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "OIDC Token Endpoint URL",
						},
						"userinfo_endpoint": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "OIDC UserInfo Endpoint URL",
						},
						"jwks_uri": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "OIDC JWKS URI",
						},
						"discovery_url": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "OIDC Discovery URL",
						},
						"certs_uri": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "OIDC Certificates URI",
						},
						"check_session_iframe": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "OIDC Check Session Iframe URL",
						},
						"end_session_endpoint": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "OIDC End Session Endpoint URL",
						},
						"openid_metadata": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "OIDC OpenID Metadata URL",
						},
						"oidc_clients": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "OIDC Client configurations",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"client_name": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "OIDC Client Name",
									},
									"client_id": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "OIDC Client ID",
									},
									"response_type": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "OIDC Response Types",
										Elem: &schema.Schema{
											Type:         schema.TypeString,
											ValidateFunc: validateOIDCResponseType,
										},
									},
									"implicit_grant": {
										Type:        schema.TypeBool,
										Optional:    true,
										Default:     false,
										Description: "OIDC Implicit Grant",
									},
									"type": {
										Type:         schema.TypeString,
										Optional:     true,
										Default:      string(client.DefaultOIDCClientType),
										Description:  "OIDC Client Type",
										ValidateFunc: validateOIDCClientType,
									},
									"redirect_uris": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "OIDC Redirect URIs",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"javascript_origins": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "OIDC JavaScript Origins",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"logout_url": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "OIDC Logout URL",
									},
									"logout_session_required": {
										Type:        schema.TypeBool,
										Optional:    true,
										Default:     false,
										Description: "OIDC Logout Session Required",
									},
									"post_logout_redirect_uri": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "OIDC Post Logout Redirect URIs",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"metadata": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "OIDC Client Metadata",
									},
									"claims": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "OIDC Claims",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"name": {
													Type:        schema.TypeString,
													Optional:    true,
													Description: "OIDC Claim Name",
												},
												"scope": {
													Type:        schema.TypeString,
													Optional:    true,
													Description: "OIDC Claim Scope",
												},
												"val": {
													Type:        schema.TypeString,
													Optional:    true,
													Description: "OIDC Claim Value",
												},
												"src": {
													Type:        schema.TypeString,
													Optional:    true,
													Description: "OIDC Claim Source",
												},
												"rule": {
													Type:        schema.TypeString,
													Optional:    true,
													Description: "OIDC Claim Rule",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},

			"app_operational": {
				Type:     schema.TypeInt,
				Optional: true,
				Computed: true,
			},
			"app_status": {
				Type:     schema.TypeInt,
				Optional: true,
				Computed: true,
			},

			"app_deployed": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"cname": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},

			"uuid_url": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},

			"agents": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"app_category": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"cert_name": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"cert_type": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"cert": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"generate_self_signed_cert": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"advanced_settings": {
				Type:     schema.TypeMap,
				Optional: true,
				Computed: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Description: "Flat map of advanced settings key/value pairs. All values are strings. " +
					"Known keys are validated; unrecognised keys are passed to the API with a warning. " +
					"Complex fields (form_post_attributes, request_parameters, custom_headers, rdp_remote_apps) must be JSON-encoded strings.",
			},
			"app_bundle": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "Application bundle name for related applications grouping.",
				ValidateFunc: validateAppBundle,
			},
			"service": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"service_type": {
							Type:     schema.TypeString,
							Required: true,
						},
						"status": {
							Type:     schema.TypeString,
							Required: true,
						},
						"access_rule": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:     schema.TypeString,
										Required: true,
									},
									"status": {
										Type:     schema.TypeString,
										Required: true,
									},
									"rule": {
										Type:     schema.TypeList,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"operator": {
													Type:     schema.TypeString,
													Required: true,
												},
												"type": {
													Type:     schema.TypeString,
													Required: true,
												},
												"value": {
													Type:     schema.TypeString,
													Required: true,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},

			"app_authentication": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"app_idp": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"app_directories": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:     schema.TypeString,
										Required: true,
									},
									"enable_mfa": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"app_groups": {
										Type:     schema.TypeList,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"name": {
													Type:     schema.TypeString,
													Required: true,
												},
												"enable_mfa": {
													Type:     schema.TypeString,
													Optional: true,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		CustomizeDiff: customizeDiffApplication,
	}
}

// customizeDiffApplication is the CustomizeDiff function for the EAA application resource
func customizeDiffApplication(ctx context.Context, d *schema.ResourceDiff, m interface{}) error {
	// Get client logger from meta
	eaaclient, err := Client(m)
	if err != nil {
		return fmt.Errorf("failed to get client: %w", err)
	}
	logger := eaaclient.Logger

	// Validate authentication methods for app type (always run this validation)
	authErr := validateAuthenticationMethodsForAppTypeWithDiff(d)
	if authErr != nil {
		return authErr
	}

	// Note: SAML validation is handled by validateSAMLSettings in the schema

	// Validate WSFED nested blocks
	err = client.ValidateWSFEDNestedBlocks(ctx, d, m, logger)

	// Validate SAML nested blocks
	if err == nil {
		err = client.ValidateSAMLNestedBlocks(ctx, d, m, logger)
	}

	// Validate OIDC nested blocks
	if err == nil {
		err = client.ValidateOIDCNestedBlocks(ctx, d, m, logger)
	}

	// Validate app bundle restrictions
	if err == nil {
		err = validateAppBundleRestrictions(d, logger)
	}

	// Keep advanced_settings validation limited to provider-owned conflicts.
	if err == nil {
		err = validateAdvancedSettingsAtPlanTime(d, m)
	}

	return err
}

// validateAdvancedSettingsAtPlanTime validates advanced settings during terraform plan
func validateAdvancedSettingsAtPlanTime(diff *schema.ResourceDiff, m interface{}) error {
	// Get client logger from meta
	eaaclient, err := Client(m)
	if err != nil {
		return fmt.Errorf("failed to get client: %w", err)
	}
	logger := eaaclient.Logger

	// Get app_type and app_profile from the diff
	appType, ok := diff.Get("app_type").(string)
	if !ok {
		return client.ErrAppTypeRequired
	}

	appProfile, ok := diff.Get("app_profile").(string)
	if !ok {
		return client.ErrAppProfileRequired
	}

	// Get advanced_settings from the diff (TypeMap)
	advRaw := diff.Get("advanced_settings")
	settings, ok := advRaw.(map[string]interface{})
	if !ok || len(settings) == 0 {
		return nil
	}

	// Restrict plan-time validation to provider-owned checks only.
	logger.Debug("Running provider-owned validation for advanced settings")

	// Validate app_auth conflicts with resource-level authentication settings.
	logger.Debug("Running app_auth conflict validation")
	if err := validateAppAuthConflictsWithResourceLevelAuth(settings, diff, logger); err != nil {
		logger.Error("App auth conflict validation failed: %v", err)
		return err
	}
	logger.Debug("App auth conflict validation passed")

	// Validate TLS Suite configuration restrictions because the provider rewrites these fields.
	if err := validateTLSSuiteRestrictions(appType, appProfile, settings); err != nil {
		return client.ErrTLSSuiteRestrictionsValidationFailed
	}

	// Validate TLS Suite required dependencies because the provider rewrites these fields.
	if err := validateTLSSuiteRequiredDependencies(settings, logger); err != nil {
		return err
	}

	return nil
}

// resourceEaaApplicationCreateTwoPhase implements the two-phase application creation approach
// Phase 1: Create app with minimal required fields
// Phase 2: Configure additional settings (agents, authentication, advanced settings, deployment)
func resourceEaaApplicationCreateTwoPhase(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}
	logger := eaaclient.Logger
	warningDiags := validateAdvancedSettingsWarningDiagnostics(d, logger)

	logger.Debug("Starting two-phase application creation")

	var appUUIDURL string
	var phase2Steps []func() error

	// ========================================
	// PHASE 1: Create minimal application
	// ========================================
	logger.Debug("Phase 1: Creating minimal application")

	minimalRequest := client.MinimalCreateAppRequest{}
	err = minimalRequest.CreateMinimalAppRequestFromSchema(ctx, d, eaaclient)
	if err != nil {
		logger.Error("Phase 1 failed: create minimal app request failed. err ", err)
		return append(warningDiags, diag.FromErr(err)...)
	}

	appResp, err := minimalRequest.CreateMinimalApplication(ctx, eaaclient)
	if err != nil {
		logger.Error("Phase 1 failed: create minimal application failed. err ", err)
		return append(warningDiags, diag.FromErr(err)...)
	}

	appUUIDURL = appResp.UUIDURL
	logger.Debug("Phase 1 succeeded: Application created with ID:", appUUIDURL)

	// Set the resource ID early so cleanup can work if later steps fail
	d.SetId(appUUIDURL)

	// ========================================
	// PHASE 2: Configure additional settings
	// ========================================
	logger.Debug("Phase 2: Configuring additional settings")

	// Prepare Phase 2 steps for potential rollback
	phase2Steps = []func() error{
		func() error {
			logger.Debug("Phase 2: Configuring agents...")
			return client.ConfigureAgents(ctx, appUUIDURL, d, eaaclient)
		},
		func() error {
			logger.Debug("Phase 2: Configuring authentication...")
			return client.ConfigureAuthentication(ctx, appUUIDURL, d, eaaclient)
		},
		func() error {
			logger.Debug("Phase 2: Configuring advanced settings...")
			return client.ConfigureAdvancedSettings(ctx, appUUIDURL, d, eaaclient)
		},
		func() error {
			logger.Debug("Phase 2: Deploying application...")
			return client.DeployExistingApplication(ctx, appUUIDURL, eaaclient)
		},
	}

	// Execute Phase 2 steps with error handling
	for i, step := range phase2Steps {
		if err := step(); err != nil {
			logger.Error("Phase 2 failed at step %d: %v", i+1, err)

			// Clean up the created application
			logger.Warn("Cleaning up created application due to Phase 2 failure...")
			if !cleanupOrphanedApp(eaaclient, appUUIDURL) {
				logger.Error("Failed to clean up orphaned app")
				// Add a warning about manual cleanup needed
				return append(append(warningDiags, diag.FromErr(err)...), diag.Diagnostic{
					Severity: diag.Warning,
					Summary:  "Application creation failed and cleanup failed",
					Detail:   fmt.Sprintf("Application %s was created but configuration failed. Manual cleanup may be required.", appUUIDURL),
				})
			}

			// Clear the state
			d.SetId("")
			return append(warningDiags, diag.FromErr(err)...)
		}
		logger.Debug("Phase 2 step %d completed successfully", i+1)
	}

	logger.Debug("Two-phase application creation completed successfully")

	// Return the read result
	return append(warningDiags, resourceEaaApplicationRead(ctx, d, m)...)
}

// resourceEaaApplicationRead function reads an existing EAA application.
// fetches application details using and maps the response to the schema attributes.

func resourceEaaApplicationRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	id := d.Id()
	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}
	var appResp client.ApplicationResponse

	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, id)

	getResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
	if err != nil {
		return diag.FromErr(err)
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		return diag.FromErr(getAppError(getResp))
	}

	// Map basic attributes
	if diags := mapBasicAttributesFromResponse(d, &appResp, eaaclient); diags != nil {
		return diags
	}

	// Map servers and tunnel hosts
	if diags := mapServersAndTunnelHostsFromResponse(d, &appResp); diags != nil {
		return diags
	}

	// Map advanced settings
	if diags := mapAdvancedSettingsFromResponse(d, &appResp); diags != nil {
		return diags
	}

	// Map agents, authentication, cert, and service
	if diags := mapAgentsAndAuthFromResponse(d, &appResp, eaaclient); diags != nil {
		return diags
	}

	// Map SAML settings
	if diags := mapSAMLSettingsFromResponse(d, &appResp); diags != nil {
		return diags
	}

	// Map WSFED settings
	if diags := mapWSFEDSettingsFromResponse(d, &appResp); diags != nil {
		return diags
	}

	// Map OIDC settings
	if diags := mapOIDCSettingsFromResponse(d, &appResp); diags != nil {
		return diags
	}

	return nil
}

// resourceEaaApplicationUpdate function updates an existing EAA application.
// fetches the application, updates it based on the changed attributes, and deploys the application.
// then calls the read function to ensure the updated data is correctly populated in the schema.

func resourceEaaApplicationUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Set the resource ID
	id := d.Id()
	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}
	warningDiags := validateAdvancedSettingsWarningDiagnostics(d, eaaclient.Logger)

	// Advanced settings validation is now handled at plan time via CustomizeDiff

	var appResp client.Application

	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, id)

	getResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
	if err != nil {
		return append(warningDiags, diag.FromErr(err)...)
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		return append(warningDiags, diag.FromErr(getAppError(getResp))...)
	}

	// Store the update request for later use after IDP assignment
	appUpdateReq := client.ApplicationUpdateRequest{}
	appUpdateReq.Application = appResp
	err = appUpdateReq.UpdateAppRequestFromSchema(ctx, d, eaaclient)
	if err != nil {
		return append(warningDiags, diag.FromErr(err)...)
	}

	currAgents, err := appResp.GetAppAgents(eaaclient)
	if err == nil {
		if agentsRaw, ok := d.GetOk("agents"); ok {
			agentList, ok := agentsRaw.([]interface{})
			if !ok {
				return append(warningDiags, diag.FromErr(ErrInvalidData)...)
			}
			var desiredAgents []string
			for _, agent := range agentList {
				if str, ok := agent.(string); ok {
					desiredAgents = append(desiredAgents, str)
				}
			}

			agentsToAssign := client.DifferenceIgnoreCase(desiredAgents, currAgents)
			agentsToUnassign := client.DifferenceIgnoreCase(currAgents, desiredAgents)

			if len(agentsToAssign) > 0 {
				var agents client.AssignAgents
				agents.AppID = id
				agents.AgentNames = append(agents.AgentNames, agentsToAssign...)
				assignErr := agents.AssignAgents(ctx, eaaclient)
				if assignErr != nil {
					return append(warningDiags, diag.FromErr(assignErr)...)
				}
			}
			if len(agentsToUnassign) > 0 {
				var agents client.AssignAgents
				agents.AppID = id
				agents.AgentNames = append(agents.AgentNames, agentsToUnassign...)

				unassignErr := agents.UnAssignAgents(ctx, eaaclient)
				if unassignErr != nil {
					return append(warningDiags, diag.FromErr(unassignErr)...)
				}
			}
		}
	}
	if d.HasChange("app_authentication") {
		authEnabledValue := "false"

		if aE, ok := d.GetOk("auth_enabled"); ok {
			authEnabled, ok := aE.(string)
			if !ok {
				return append(warningDiags, diag.FromErr(ErrInvalidData)...)
			}
			authEnabledValue = authEnabled
		}

		if authEnabledValue == "true" {
			if appAuth, ok := d.GetOk("app_authentication"); ok {
				appUUIDURL := id
				appIDPMembership, membershipErr := appResp.GetAppIdpMembership(eaaclient)
				if membershipErr != nil {
					return append(warningDiags, diag.FromErr(membershipErr)...)
				}
				if appIDPMembership != nil {
					appIdp := client.AppIdp{
						App: appUUIDURL,
						IDP: appIDPMembership.UUIDURL,
					}
					err = appIdp.UnAssignIDP(eaaclient)
					if err != nil {
						eaaclient.Logger.Error("idp unassign error err ", err)
						return append(warningDiags, diag.FromErr(err)...)
					}
				}
				appAuthList, ok := appAuth.([]interface{})
				if !ok {
					return append(warningDiags, diag.FromErr(ErrInvalidData)...)
				}
				if appAuthList == nil {
					return append(warningDiags, diag.FromErr(ErrInvalidData)...)
				}
				if len(appAuthList) > 0 {
					appAuthenticationMap, ok := appAuthList[0].(map[string]interface{})
					if !ok {
						return append(warningDiags, diag.FromErr(ErrInvalidData)...)
					}
					if appAuthenticationMap == nil {
						eaaclient.Logger.Error("invalid authentication data")
						return append(warningDiags, diag.FromErr(ErrInvalidData)...)
					}

					// Check if app_idp key is present
					if appIDPName, ok := appAuthenticationMap["app_idp"].(string); ok {
						idpData, getIDPErr := client.GetIdpWithName(ctx, eaaclient, appIDPName)
						if getIDPErr != nil || idpData == nil {
							eaaclient.Logger.Error("get idp with name error, err ", getIDPErr)
							return append(warningDiags, diag.FromErr(getIDPErr)...)
						}

						eaaclient.Logger.Debug("Starting IDP assignment in UPDATE flow")
						eaaclient.Logger.Debug("Assigning IDP to application in UPDATE")
						eaaclient.Logger.Debug("app_uuid_url", "value", appUUIDURL)
						eaaclient.Logger.Debug("idpData.UUIDURL", "value", idpData.UUIDURL)

						appIdp := client.AppIdp{
							App: appUUIDURL,
							IDP: idpData.UUIDURL,
						}
						err = appIdp.AssignIDP(eaaclient)
						if err != nil {
							eaaclient.Logger.Error("IDP assign error in UPDATE", "error", err)
							return append(warningDiags, diag.FromErr(err)...)
						}
						eaaclient.Logger.Debug("IDP assigned successfully in UPDATE", "app_name", appResp.Name, "idp", appIDPName)

						// check if app_directories are present
						if appDirs, ok := appAuthenticationMap["app_directories"]; ok {
							eaaclient.Logger.Debug("Starting directory assignment in UPDATE...")
							directoryErr := idpData.AssignIdpDirectories(ctx, appDirs, appUUIDURL, eaaclient)
							if directoryErr != nil {
								eaaclient.Logger.Error("Directory assignment error in UPDATE", "error", directoryErr)
								return append(warningDiags, diag.FromErr(directoryErr)...)
							}
							eaaclient.Logger.Debug("Directory assignment completed successfully in UPDATE")
						} else {
							eaaclient.Logger.Debug("No app_directories found in UPDATE, skipping directory assignment")
						}

						eaaclient.Logger.Debug("IDP assignment complete in UPDATE flow")
					}
				}
			}
		}
	}

	// Check if the "service" attribute is present and has changed
	if d.HasChange("service") {
		// Get the service attribute as a list (since it is defined as a list in the schema)
		services, ok := d.Get("service").([]interface{})
		if !ok {
			return append(warningDiags, diag.FromErr(ErrInvalidData)...)
		}

		if len(services) > 0 {
			appUUIDURL := appResp.UUIDURL
			appSrv, serviceErr := client.GetACLService(eaaclient, appUUIDURL)
			if serviceErr != nil {
				return append(warningDiags, diag.FromErr(serviceErr)...)
			}

			aclSrv, extractErr := client.ExtractACLService(ctx, d, eaaclient)
			if extractErr != nil {
				return append(warningDiags, diag.FromErr(extractErr)...)
			}

			if appSrv.Status != aclSrv.Status {
				appSrv.Status = aclSrv.Status
				if serviceErr := appSrv.EnableService(eaaclient); serviceErr != nil {
					return append(warningDiags, diag.FromErr(serviceErr)...)
				}
			}
			if d.HasChange("service.0.access_rule") {
				// Fetch existing rules
				existingACLResponse, rulesErr := client.GetAccessControlRules(eaaclient, appSrv.UUIDURL)
				if rulesErr != nil {
					return append(warningDiags, diag.FromErr(rulesErr)...)
				}
				existingRulesMap := make(map[string]client.AccessRule)
				for _, rule := range existingACLResponse.ACLRules {
					existingRulesMap[rule.Name] = rule
				}

				// Convert new rules into a map for easy comparison
				newRulesMap := make(map[string]client.AccessRule)
				for _, rule := range aclSrv.ACLRules {
					newRulesMap[rule.Name] = rule
				}

				// Handle deletions
				for name, existingRule := range existingRulesMap {
					if _, exists := newRulesMap[name]; !exists {
						if deleteErr := existingRule.DeleteAccessRule(ctx, eaaclient, appSrv.UUIDURL); deleteErr != nil {
							return append(warningDiags, diag.FromErr(deleteErr)...)
						}
					}
				}

				// Handle creations and modifications
				for name, newRule := range newRulesMap {
					if existingRule, exists := existingRulesMap[name]; exists {
						if !existingRule.IsEqual(newRule) {
							newRule.UUID_URL = existingRule.UUID_URL
							if modifyErr := newRule.ModifyAccessRule(ctx, eaaclient, appSrv.UUIDURL); modifyErr != nil {
								return append(warningDiags, diag.FromErr(modifyErr)...)
							}
						}
					} else {
						// Create new rule
						if createErr := newRule.CreateAccessRule(ctx, eaaclient, appSrv.UUIDURL); createErr != nil {
							return append(warningDiags, diag.FromErr(createErr)...)
						}
					}
				}
			}
		}
	}

	// Now perform the PUT call to update advanced settings AFTER IDP assignment is complete
	eaaclient.Logger.Debug("Performing PUT call after IDP assignment in UPDATE flow")
	err = appUpdateReq.UpdateApplication(ctx, eaaclient)
	if err != nil {
		eaaclient.Logger.Error("PUT call failed after IDP assignment in UPDATE", "error", err)
		return append(warningDiags, diag.FromErr(err)...)
	}
	eaaclient.Logger.Debug("PUT call completed successfully in UPDATE flow")

	// Add delay before deploy in UPDATE flow to ensure all operations are complete
	eaaclient.Logger.Debug("waiting before deploy in UPDATE flow...")

	err = appUpdateReq.DeployApplication(eaaclient)
	if err != nil {
		return append(warningDiags, diag.FromErr(err)...)
	}

	return append(warningDiags, resourceEaaApplicationRead(ctx, d, m)...)
}

// resourceEaaApplicationDelete function deletes an existing EAA application.
// sends a delete request to the EAA client to remove the application.
func resourceEaaApplicationDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Read the resource ID from d
	id := d.Id()
	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}
	var appResp client.ApplicationDataModel

	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, id)
	getResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
	if err != nil {
		return diag.FromErr(err)
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		return diag.FromErr(getAppError(getResp))
	}
	err = appResp.DeleteApplication(eaaclient)
	if err != nil {
		return diag.FromErr(err)
	}

	// Set the resource ID to mark it as deleted
	d.SetId("")

	return nil
}
