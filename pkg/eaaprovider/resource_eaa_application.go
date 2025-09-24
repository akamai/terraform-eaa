package eaaprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	ErrGetApp      = errors.New("app get failed")
	ErrInvalidData = errors.New("invalid data in schema")
)



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
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
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
										Type:        schema.TypeString,
										Optional:    true,
										Default:     "post",
										Description: "SAML SP Response Binding",
									},
									"token_life": {
										Type:        schema.TypeInt,
										Optional:    true,
										Default:     3600,
										Description: "SAML SP Token Lifetime (seconds)",
									},
									"encr_algo": {
										Type:        schema.TypeString,
										Optional:    true,
										Default:     "aes256-cbc",
										Description: "SAML SP Encryption Algorithm",
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
										Type:        schema.TypeString,
										Optional:    true,
										Default:     "SHA256",
										Description: "SAML IDP Signing Algorithm",
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
										Type:        schema.TypeString,
										Optional:    true,
										Default:     "email",
										Description: "SAML Subject format",
									},
									"src": {
										Type:        schema.TypeString,
										Optional:    true,
										Default:     "user.email",
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
										Optional:    true,
										Description: "SAML Attribute name",
									},
									"value": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "SAML Attribute value",
									},
								},
							},
						},
					},
				},
			},
			"wsfed": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
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
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
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
											Type: schema.TypeString,
										},
									},
									"implicit_grant": {
										Type:        schema.TypeBool,
										Optional:    true,
										Default:     false,
										Description: "OIDC Implicit Grant",
									},
									"type": {
										Type:        schema.TypeString,
										Optional:    true,
										Default:     "standard",
										Description: "OIDC Client Type",
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
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "Advanced settings in JSON format. Use jsonencode() to convert HCL map to JSON.",
				Default:      "{}",
				ValidateFunc: validateAdvancedSettingsJSON,
			},
			"_validation_trigger": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				ForceNew:    true,
				Description: "Internal field to trigger CustomizeDiff",
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

	// Always set a new validation trigger to force CustomizeDiff to run
	d.SetNew("_validation_trigger", "validation-trigger")

	err = validateAdvancedSettingsAtPlanTime(ctx, d, m)

	// Validate authentication methods for app type (always run this validation)
	authErr := validateAuthenticationMethodsForAppTypeWithDiff(d)
	if authErr != nil {
		return authErr
	}

	// If advanced settings validation failed, return that error
	if err != nil {
		return err
	}

	// Note: SAML validation is handled by validateSAMLSettings in the schema

	// Validate WSFED nested blocks
	if err == nil {
		err = validateWSFEDNestedBlocks(ctx, d, m, logger)
	}

	// Validate SAML nested blocks
	if err == nil {
		err = validateSAMLNestedBlocks(ctx, d, m, logger)
	}

	// Validate OIDC nested blocks
	if err == nil {
		err = validateOIDCNestedBlocks(ctx, d, m, logger)
	}

	return err
}

// validateAdvancedSettingsAtPlanTime validates advanced settings during terraform plan
func validateAdvancedSettingsAtPlanTime(ctx context.Context, diff *schema.ResourceDiff, m interface{}) error {
	// Get client logger from meta
	eaaclient, err := Client(m)
	if err != nil {
		return fmt.Errorf("failed to get client: %w", err)
	}
	logger := eaaclient.Logger

	// Get app_type, app_profile, and client_app_mode from the diff
	appType, ok := diff.Get("app_type").(string)
	if !ok {
		return client.ErrAppTypeRequired
	}

	appProfile, ok := diff.Get("app_profile").(string)
	if !ok {
		return client.ErrAppProfileRequired
	}

	clientAppMode, ok := diff.Get("client_app_mode").(string)
	if !ok {
		clientAppMode = "" // Default to empty if not provided
	}

	// For bookmark and saas, advanced_settings should not be allowed at all
	// These app types should use resource-level configuration instead
	if appType == "bookmark" || appType == "saas" {
		advancedSettingsStr, ok := diff.Get("advanced_settings").(string)
		if ok && advancedSettingsStr != "" && advancedSettingsStr != "{}" {
			return client.ErrAdvancedSettingsNotAllowedForAppType
		}
		return nil
	}

	// Get advanced_settings from the diff
	advancedSettingsStr, ok := diff.Get("advanced_settings").(string)
	if !ok || advancedSettingsStr == "" || advancedSettingsStr == "{}" {
		// No advanced settings to validate
		return nil
	}

	// Parse the JSON
	var settings map[string]interface{}
	if err := json.Unmarshal([]byte(advancedSettingsStr), &settings); err != nil {
		return client.ErrAdvancedSettingsInvalidJSONFormat
	}

	// STEP 1: Use generic validation system to validate all fields
	logger.Debug("Running generic validation for advanced settings")
	if err := ValidateAdvancedSettings(settings, appType, appProfile, clientAppMode, logger); err != nil {
		logger.Error("Generic validation failed: %v", err)
		return err
	}
	logger.Debug("Generic validation passed")

	// STEP 1.5: Validate conflicts between advanced settings and resource-level settings
	logger.Debug("Running conflict validation for advanced settings")
	if err := ValidateAdvancedSettingsConflicts(settings, logger); err != nil {
		logger.Error("Conflict validation failed: %v", err)
		return err
	}
	logger.Debug("Conflict validation passed")

	// STEP 1.6: Validate app_auth conflicts with resource-level authentication settings
	logger.Debug("Running app_auth conflict validation")
	if err := validateAppAuthConflictsWithResourceLevelAuth(settings, diff, logger); err != nil {
		logger.Error("App auth conflict validation failed: %v", err)
		return err
	}
	logger.Debug("App auth conflict validation passed")

	// STEP 1.7: Validate context-dependent rules
	logger.Debug("Running context-dependent validation")
	if err := ValidateAdvancedSettingsContext(settings, appType, appProfile, clientAppMode, logger); err != nil {
		logger.Error("Context-dependent validation failed: %v", err)
		return err
	}
	logger.Debug("Context-dependent validation passed")

	// STEP 1.8: Validate field dependencies
	logger.Debug("Running field dependencies validation")
	if err := ValidateAdvancedSettingsDependencies(settings, logger); err != nil {
		logger.Error("Field dependencies validation failed: %v", err)
		return err
	}
	logger.Debug("Field dependencies validation passed")

	// STEP 2: API-dependent validations (cannot be handled by generic system)
	// Validate API-dependent settings (TLS custom suite name, etc.)
	if err := ValidateAdvancedSettingsAPIDependent(settings, m, logger); err != nil {
		return err
	}

	// Validate custom headers configuration (complex custom logic)
	if err := validateCustomHeadersConfiguration(settings, appType, logger); err != nil {
		return client.ErrCustomHeadersValidationFailed
	}

	// Validate miscellaneous configuration (complex custom logic)
	if err := validateMiscellaneousConfiguration(settings, appType, appProfile, logger); err != nil {
		return client.ErrMiscellaneousValidationFailed
	}

	// Validate health check configuration (skip for tunnel apps)
	if appType != "tunnel" {
		logger.Debug("Validating health check for app_type: %s", appType)
		if err := validateHealthCheckConfiguration(settings, appType, appProfile, logger); err != nil {
			logger.Error("Health check validation failed for app_type %s: %v", appType, err)
			return err
		}
	} else {
		logger.Debug("Skipping health check validation for tunnel app")
	}

	// Validate server load balancing configuration (complex custom logic)
	if err := validateServerLoadBalancingConfiguration(settings, appType, appProfile, logger); err != nil {
		return client.ErrServerLoadBalancingValidationFailed
	}

	// Validate related applications configuration (complex custom logic)
	if err := validateRelatedApplications(settings, appType, appProfile, logger); err != nil {
		return client.ErrRelatedApplicationsNotSupportedForProfile
	}

	return nil
}

// Wrapper function that handles cleanup on failure
func resourceEaaApplicationCreateWrapper(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Step 1: Call the original create function
	diags := resourceEaaApplicationCreate(ctx, d, m)

	// Step 2: Check if creation was successful
	if len(diags) == 0 {
		// Success - nothing to do
		return diags
	}

	// Step 3: Check if we have any errors
	hasError := false
	for _, diagnostic := range diags {
		if diagnostic.Severity == diag.Error {
			hasError = true
			break
		}
	}

	if !hasError {
		// Only warnings, no errors - return as is
		return diags
	}

	// Step 4: We have errors - check if app was created
	appID := d.Id()
	if appID == "" {
		// No ID set, original function failed early - return original error
		return diags
	}

	// Step 5: App was created but something failed later
	// This is our problem case - clean up the orphaned app
	eaaclient := m.(*client.EaaClient)
	logger := eaaclient.Logger

	logger.Warn("App creation failed but app exists in EAA, cleaning up...")

	// Clean up the orphaned app
	cleanupSuccess := cleanupOrphanedApp(ctx, eaaclient, appID)

	// Clear the state
	d.SetId("")

	if cleanupSuccess {
		logger.Info("Successfully cleaned up orphaned app:", appID)
	} else {
		logger.Error("Failed to clean up orphaned app:", appID)
		// Add a warning about manual cleanup needed
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "App creation failed and cleanup was incomplete",
			Detail:   client.ErrAppCleanupIncomplete.Error(),
		})
	}

	// Return the original error
	return diags
}

// getValidCipherSuitesFromAPI fetches valid TLS cipher suites from the API
// Returns empty slice if API call fails to prevent validation blocking
func getValidCipherSuitesFromAPI(meta interface{}) ([]string, error) {
	eaaclient, err := Client(meta)
	if err != nil {
		return []string{}, err
	}

	// For validation purposes, we need a dummy app UUID URL
	// In practice, this should be the actual app UUID URL being validated
	// For now, we'll use a placeholder that works with the API
	dummyAppUUID := "dummy-app-uuid-for-validation"

	tlsResponse, err := client.GetTLSCipherSuites(eaaclient, dummyAppUUID)
	if err != nil {
		// Return empty slice instead of error to prevent validation blocking
		return []string{}, nil
	}

	// Extract cipher suite names from API response
	cipherSuites := make([]string, 0, len(tlsResponse.TLSCipherSuite))
	for name := range tlsResponse.TLSCipherSuite {
		cipherSuites = append(cipherSuites, name)
	}

	return cipherSuites, nil
}

// Cleanup function for orphaned apps
func cleanupOrphanedApp(ctx context.Context, eaaclient *client.EaaClient, appID string) bool {
	logger := eaaclient.Logger
	logger.Debug("Starting cleanup for orphaned app:", appID)

	// Check if app exists in EAA
	var appResp client.ApplicationDataModel
	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, appID)

	getResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
	if err != nil || getResp.StatusCode != 200 {
		logger.Debug("App not found in EAA, no cleanup needed")
		return true
	}

	logger.Debug("App found in EAA, proceeding with deletion...")

	// Delete the app directly
	deleteErr := appResp.DeleteApplication(eaaclient)
	if deleteErr != nil {
		logger.Error("Failed to delete app during cleanup:", deleteErr)
		return false
	}

	verifyResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
	if err == nil && verifyResp.StatusCode == 200 {
		logger.Error("App still exists after deletion attempt")
		return false
	}

	logger.Debug("App successfully deleted and verified")
	return true
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

	logger.Info("Starting two-phase application creation")

	var app_uuid_url string
	var phase2Steps []func() error

	// ========================================
	// PHASE 1: Create minimal application
	// ========================================
	logger.Info("Phase 1: Creating minimal application")

	minimalRequest := client.MinimalCreateAppRequest{}
	err = minimalRequest.CreateMinimalAppRequestFromSchema(ctx, d, eaaclient)
	if err != nil {
		logger.Error("Phase 1 failed: create minimal app request failed. err ", err)
		return diag.FromErr(err)
	}

	appResp, err := minimalRequest.CreateMinimalApplication(ctx, eaaclient)
	if err != nil {
		logger.Error("Phase 1 failed: create minimal application failed. err ", err)
		return diag.FromErr(err)
	}

	app_uuid_url = appResp.UUIDURL
	logger.Info("Phase 1 succeeded: Application created with ID:", app_uuid_url)

	// Set the resource ID early so cleanup can work if later steps fail
	d.SetId(app_uuid_url)

	// ========================================
	// PHASE 2: Configure additional settings
	// ========================================
	logger.Info("Phase 2: Configuring additional settings")

	// Prepare Phase 2 steps for potential rollback
	phase2Steps = []func() error{
		func() error {
			logger.Debug("Phase 2: Configuring agents...")
			return client.ConfigureAgents(ctx, app_uuid_url, d, eaaclient)
		},
		func() error {
			logger.Debug("Phase 2: Configuring authentication...")
			return client.ConfigureAuthentication(ctx, app_uuid_url, d, eaaclient)
		},
		func() error {
			logger.Debug("Phase 2: Configuring advanced settings...")
			return client.ConfigureAdvancedSettings(ctx, app_uuid_url, d, eaaclient)
		},
		func() error {
			logger.Debug("Phase 2: Deploying application...")
			return client.DeployExistingApplication(ctx, app_uuid_url, eaaclient)
		},
	}

	// Execute Phase 2 steps with error handling
	for i, step := range phase2Steps {
		if err := step(); err != nil {
			logger.Error("Phase 2 failed at step %d: %v", i+1, err)

			// Clean up the created application
			logger.Warn("Cleaning up created application due to Phase 2 failure...")
			if !cleanupOrphanedApp(ctx, eaaclient, app_uuid_url) {
				logger.Error("Failed to clean up orphaned app")
				// Add a warning about manual cleanup needed
				return append(diag.FromErr(err), diag.Diagnostic{
					Severity: diag.Warning,
					Summary:  "Application creation failed and cleanup failed",
					Detail:   fmt.Sprintf("Application %s was created but configuration failed. Manual cleanup may be required.", app_uuid_url),
				})
			}

			// Clear the state
			d.SetId("")
			return diag.FromErr(err)
		}
		logger.Debug("Phase 2 step %d completed successfully", i+1)
	}

	logger.Info("Two-phase application creation completed successfully")

	// Return the read result
	return resourceEaaApplicationRead(ctx, d, m)
}

// resourceEaaApplicationCreate function is responsible for creating a new EAA application.
// constructs the application creation request using data from the schema and creates the application.
// also handles assigning agents and handling authentication settings if auth_enabled is true.
// updates the application and deploys it, then sets the resource ID.

func resourceEaaApplicationCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	eaaclient, err := Client(m)
	if err != nil {
		return diag.FromErr(err)
	}
	logger := eaaclient.Logger

	// Advanced settings validation is now handled at plan time via CustomizeDiff

	createRequest := client.CreateAppRequest{}
	err = createRequest.CreateAppRequestFromSchema(ctx, d, eaaclient)
	if err != nil {
		logger.Error("create Application failed. err ", err)
		return diag.FromErr(err)
	}

	appResp, err := createRequest.CreateApplication(ctx, eaaclient)
	if err != nil {
		logger.Error("create Application failed. err ", err)
		return diag.FromErr(err)
	}

	app_uuid_url := appResp.UUIDURL
	app := client.Application{}
	app.FromResponse(appResp)

	// Set the resource ID early so cleanup can work if later steps fail
	d.SetId(app_uuid_url)

	if agentsRaw, ok := d.GetOk("agents"); ok {
		agentsList := agentsRaw.([]interface{})
		var agents client.AssignAgents
		agents.AppId = app_uuid_url
		for _, v := range agentsList {
			if name, ok := v.(string); ok {
				agents.AgentNames = append(agents.AgentNames, name)
			}
		}
		err := agents.AssignAgents(ctx, eaaclient)
		if err != nil {
			return diag.FromErr(err)
		}
		logger.Debug("create Application: assigning agents succeeded.")
	}

	// Store the update request for later use after IDP assignment
	appUpdateReq := client.ApplicationUpdateRequest{}
	appUpdateReq.Application = app
	err = appUpdateReq.UpdateAppRequestFromSchema(ctx, d, eaaclient)
	if err != nil {
		return diag.FromErr(err)
	}

	auth_enabled := "false"

	if aE, ok := d.GetOk("auth_enabled"); ok {
		auth_enabled = aE.(string)
	}

	if auth_enabled == "true" {
		if appAuth, ok := d.GetOk("app_authentication"); ok {
			appAuthList := appAuth.([]interface{})
			if appAuthList == nil {
				return diag.FromErr(ErrInvalidData)
			}
			if len(appAuthList) > 0 {
				appAuthenticationMap := appAuthList[0].(map[string]interface{})
				if appAuthenticationMap == nil {
					logger.Error("invalid authentication data")
					return diag.FromErr(ErrInvalidData)
				}

				// Check if app_idp key is present
				if app_idp_name, ok := appAuthenticationMap["app_idp"].(string); ok {
					idpData, err := client.GetIdpWithName(ctx, eaaclient, app_idp_name)
					if err != nil || idpData == nil {
						logger.Error("get idp with name error, err ", err)
						return diag.FromErr(err)
					}
					logger.Debug("app.Name: ", app.Name, "app_idp_name: ", app_idp_name, "idpData.UUIDURL: ", idpData.UUIDURL)

					logger.Debug("Assigning IDP to application")

					appIdp := client.AppIdp{
						App: app_uuid_url,
						IDP: idpData.UUIDURL,
					}
					err = appIdp.AssignIDP(eaaclient)
					if err != nil {
						logger.Error("IDP assign error: ", err)
						return diag.Errorf("assigning IDP to the app failed: %v", err)
					}
					logger.Debug("IDP assigned successfully, app.Name = ", app.Name, "idp = ", app_idp_name)

					// check if app_directories are present
					if appDirs, ok := appAuthenticationMap["app_directories"]; ok {
						logger.Debug("Starting directory assignment...")
						err := idpData.AssignIdpDirectories(ctx, appDirs, app_uuid_url, eaaclient)
						if err != nil {
							logger.Error("Directory assignment error: ", err)
							return diag.FromErr(err)
						}
						logger.Debug("Directory assignment completed successfully")
					} else {
						logger.Debug("No app_directories found, skipping directory assignment")
					}
				}
			}
		}
	}

	// Verify IDP assignment is complete before proceeding
	if auth_enabled == "true" {
		logger.Debug("Starting IDP assignment verification")
		logger.Debug("auth_enabled", "value", auth_enabled)
		logger.Debug("app_uuid_url", "value", app_uuid_url)

		logger.Debug("Waiting 30 seconds for IDP assignment to propagate...")

		// Verify the application has the correct authentication settings
		apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, app_uuid_url)
		logger.Debug("Fetching application details", "url", apiURL)

		var appResp client.ApplicationResponse
		getResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
		if err != nil {
			logger.Error("Failed to verify authentication settings", "error", err)
			return diag.FromErr(err)
		}
		if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
			logger.Error("Failed to verify authentication settings - bad status code", "status_code", getResp.StatusCode)
			return diag.FromErr(client.ErrAuthSettingsVerificationFailed)
		}

		// Check if the application has authentication enabled
		if appResp.AuthEnabled != "true" {
			logger.Debug("Authentication not yet enabled, waiting additional 30 seconds...")

			// Check again after additional wait
			_, err = eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
			if err != nil {
				logger.Error("Failed to verify authentication settings after additional wait", "error", err)
				return diag.FromErr(err)
			}
			logger.Debug("After additional wait - appResp.AuthEnabled", "value", appResp.AuthEnabled)
		} else {
			logger.Debug("Authentication is properly enabled!")
		}

		logger.Debug("IDP assignment verification complete")
	}

	// Now perform the PUT call to update advanced settings AFTER IDP assignment is complete
	logger.Debug("Performing PUT call after IDP assignment")
	err = appUpdateReq.UpdateApplication(ctx, eaaclient)
	if err != nil {
		logger.Error("PUT call failed after IDP assignment", "error", err)
		return diag.FromErr(err)
	}
	logger.Debug("PUT call completed successfully")

	_, ok := d.Get("service").([]interface{})
	if ok {
		aclSrv, err := client.ExtractACLService(ctx, d, eaaclient)
		if err != nil {
			return diag.FromErr(err)
		}
		appSrv, err := client.GetACLService(eaaclient, app_uuid_url)
		if err != nil {
			return diag.FromErr(err)
		}
		if appSrv.Status != aclSrv.Status {
			appSrv.Status = aclSrv.Status
			err := appSrv.EnableService(eaaclient)
			if err != nil {
				return diag.FromErr(err)
			}
		}
		if len(aclSrv.ACLRules) > 0 {
			for _, aclRule := range aclSrv.ACLRules {
				err := aclRule.CreateAccessRule(ctx, eaaclient, appSrv.UUIDURL)
				if err != nil {
					return diag.FromErr(err)
				}
			}
		}
	}

	logger.Debug("deploying application after all configuration steps are complete...")
	err = app.DeployApplication(eaaclient)
	if err != nil {
		return diag.FromErr(err)
	}

	// Resource ID already set earlier, just return the read result
	return resourceEaaApplicationRead(ctx, d, m)
}

// resourceEaaApplicationRead function reads an existing EAA application.
// fetches application details using and maps the response to the schema attributes.

func resourceEaaApplicationRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	id := d.Id()
	eaaclient := m.(*client.EaaClient)
	var appResp client.ApplicationResponse

	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, id)

	getResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
	if err != nil {
		return diag.FromErr(err)
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		_, _ = client.FormatErrorResponse(getResp)
		getAppErrMsg := client.ErrGetAppFailed
		return diag.FromErr(getAppErrMsg)
	}
	attrs := make(map[string]interface{})
	attrs["name"] = appResp.Name
	if appResp.Description != nil {
		attrs["description"] = *appResp.Description
	}

	aProfile := client.AppProfileInt(appResp.AppProfile)
	profileString, err := aProfile.String()
	if err != nil {
		eaaclient.Logger.Info("error converting app_profile")
	}
	attrs["app_profile"] = profileString

	aType := client.ClientAppTypeInt(appResp.AppType)
	typeString, err := aType.String()
	if err != nil {
		eaaclient.Logger.Info("error converting app_type")
	}
	attrs["app_type"] = typeString

	aMode := client.ClientAppModeInt(appResp.ClientAppMode)
	modeString, err := aMode.String()
	if err != nil {
		eaaclient.Logger.Info("error converting client_app_mode")
	}
	attrs["client_app_mode"] = modeString

	// DomainSuffix is already a string, no need to convert
	attrs["domain"] = appResp.DomainSuffix

	if appResp.Host != nil {
		attrs["host"] = *appResp.Host
	}
	if appResp.BookmarkURL != "" {
		attrs["bookmark_url"] = appResp.BookmarkURL
	}

	if appResp.OriginHost != nil && *appResp.OriginHost != "" {
		attrs["origin_host"] = *appResp.OriginHost
		attrs["orig_tls"] = appResp.OrigTLS
		attrs["origin_port"] = appResp.OriginPort
	}

	attrs["pop"] = appResp.POP
	attrs["popname"] = appResp.POPName
	attrs["popregion"] = appResp.POPRegion

	attrs["auth_enabled"] = appResp.AuthEnabled
	attrs["app_deployed"] = appResp.AppDeployed
	attrs["app_operational"] = appResp.AppOperational
	attrs["app_status"] = appResp.AppStatus
	attrs["saml"] = appResp.SAML
	attrs["oidc"] = appResp.Oidc
	attrs["wsfed"] = appResp.WSFED

	if appResp.CName != nil {
		attrs["cname"] = *appResp.CName
	}

	// Add missing fields that are showing as null in state
	// Always set app_category, even if empty, to avoid null in state
	if appResp.AppCategory.Name != "" {
		attrs["app_category"] = appResp.AppCategory.Name
	} else {
		attrs["app_category"] = ""
	}

	// Always set cert, even if empty, to avoid null in state
	if appResp.Cert != nil {
		attrs["cert"] = *appResp.Cert
	} else {
		attrs["cert"] = ""
	}

	attrs["uuid_url"] = appResp.UUIDURL

	// Add more fields to populate null values
	// Note: ssl_ca_cert is not in the schema, so we can't set it

	if err := client.SetAttrs(d, attrs); err != nil {
		return diag.FromErr(err)
	}

	servers := make([]map[string]interface{}, len(appResp.Servers))
	for i, server := range appResp.Servers {
		servers[i] = map[string]interface{}{
			"origin_host":     server.OriginHost,
			"orig_tls":        server.OrigTLS,
			"origin_port":     server.OriginPort,
			"origin_protocol": server.OriginProtocol,
		}
	}

	err = d.Set("servers", servers)
	if err != nil {
		return diag.FromErr(err)
	}

	if client.ClientAppTypeInt(appResp.AppType) == client.APP_TYPE_TUNNEL {
		tunnelInternalHosts := make([]map[string]interface{}, len(appResp.TunnelInternalHosts))

		for i, host := range appResp.TunnelInternalHosts {
			tunnelInternalHosts[i] = map[string]interface{}{
				"host":       host.Host,
				"port_range": host.PortRange,
				"proto_type": host.ProtoType,
			}
		}
		err = d.Set("tunnel_internal_hosts", tunnelInternalHosts)
		if err != nil {
			return diag.FromErr(err)
		}
	}

	// Convert advanced settings to JSON format
	advSettingsMap := make(map[string]interface{})

	// Add all the advanced settings fields
	advSettingsMap["g2o_enabled"] = appResp.AdvancedSettings.G2OEnabled
	if appResp.AdvancedSettings.G2ONonce != nil {
		advSettingsMap["g2o_nonce"] = *appResp.AdvancedSettings.G2ONonce
	}
	if appResp.AdvancedSettings.G2OKey != nil {
		advSettingsMap["g2o_key"] = *appResp.AdvancedSettings.G2OKey
	}
	advSettingsMap["is_ssl_verification_enabled"] = appResp.AdvancedSettings.IsSSLVerificationEnabled
	advSettingsMap["ignore_cname_resolution"] = appResp.AdvancedSettings.IgnoreCnameResolution
	advSettingsMap["edge_authentication_enabled"] = appResp.AdvancedSettings.EdgeAuthenticationEnabled
	advSettingsMap["edge_cookie_key"] = appResp.AdvancedSettings.EdgeCookieKey
	advSettingsMap["sla_object_url"] = appResp.AdvancedSettings.SLAObjectURL

	advSettingsMap["x_wapp_read_timeout"] = appResp.AdvancedSettings.XWappReadTimeout
	if appResp.AdvancedSettings.InternalHostname != nil {
		advSettingsMap["internal_hostname"] = *appResp.AdvancedSettings.InternalHostname
	}
	advSettingsMap["internal_host_port"] = appResp.AdvancedSettings.InternalHostPort
	advSettingsMap["wildcard_internal_hostname"] = appResp.AdvancedSettings.WildcardInternalHostname
	advSettingsMap["ip_access_allow"] = appResp.AdvancedSettings.IPAccessAllow

	advSettingsMap["allow_cors"] = appResp.AdvancedSettings.AllowCORS
	advSettingsMap["cors_origin_list"] = appResp.AdvancedSettings.CORSOriginList
	advSettingsMap["cors_method_list"] = appResp.AdvancedSettings.CORSMethodList
	advSettingsMap["cors_header_list"] = appResp.AdvancedSettings.CORSHeaderList
	advSettingsMap["cors_support_credential"] = appResp.AdvancedSettings.CORSSupportCredential

	advSettingsMap["websocket_enabled"] = appResp.AdvancedSettings.WebSocketEnabled
	advSettingsMap["sticky_agent"] = appResp.AdvancedSettings.StickyAgent
	if appResp.AdvancedSettings.AppCookieDomain != nil {
		advSettingsMap["app_cookie_domain"] = *appResp.AdvancedSettings.AppCookieDomain
	}
	if appResp.AdvancedSettings.LogoutURL != nil {
		advSettingsMap["logout_url"] = *appResp.AdvancedSettings.LogoutURL
	}
	advSettingsMap["sentry_redirect_401"] = appResp.AdvancedSettings.SentryRedirect401

	advSettingsMap["acceleration"] = appResp.AdvancedSettings.Acceleration
	advSettingsMap["anonymous_server_conn_limit"] = appResp.AdvancedSettings.AnonymousServerConnLimit
	advSettingsMap["anonymous_server_request_limit"] = appResp.AdvancedSettings.AnonymousServerReqLimit
	advSettingsMap["app_auth"] = appResp.AdvancedSettings.AppAuth
	advSettingsMap["app_auth_domain"] = appResp.AdvancedSettings.AppAuthDomain
	advSettingsMap["app_client_cert_auth"] = appResp.AdvancedSettings.AppClientCertAuth
	advSettingsMap["app_location"] = appResp.AdvancedSettings.AppLocation
	advSettingsMap["app_server_read_timeout"] = appResp.AdvancedSettings.AppServerReadTimeout
	advSettingsMap["authenticated_server_conn_limit"] = appResp.AdvancedSettings.AuthenticatedServerConnLimit
	advSettingsMap["authenticated_server_request_limit"] = appResp.AdvancedSettings.AuthenticatedServerReqLimit
	advSettingsMap["client_cert_auth"] = appResp.AdvancedSettings.ClientCertAuth
	advSettingsMap["client_cert_user_param"] = appResp.AdvancedSettings.ClientCertUserParam
	advSettingsMap["cookie_domain"] = convertStringPointerToString(appResp.AdvancedSettings.CookieDomain)
	advSettingsMap["disable_user_agent_check"] = appResp.AdvancedSettings.DisableUserAgentCheck
	advSettingsMap["domain_exception_list"] = appResp.AdvancedSettings.DomainExceptionList
	advSettingsMap["edge_transport_manual_mode"] = appResp.AdvancedSettings.EdgeTransportManualMode
	advSettingsMap["edge_transport_property_id"] = appResp.AdvancedSettings.EdgeTransportPropertyID
	advSettingsMap["enable_client_side_xhr_rewrite"] = appResp.AdvancedSettings.EnableClientSideXHRRewrite
	advSettingsMap["external_cookie_domain"] = appResp.AdvancedSettings.ExternalCookieDomain
	advSettingsMap["force_ip_route"] = appResp.AdvancedSettings.ForceIPRoute
	advSettingsMap["force_mfa"] = appResp.AdvancedSettings.ForceMFA
	advSettingsMap["form_post_attributes"] = appResp.AdvancedSettings.FormPostAttributes
	advSettingsMap["form_post_url"] = appResp.AdvancedSettings.FormPostURL
	advSettingsMap["forward_ticket_granting_ticket"] = appResp.AdvancedSettings.ForwardTicketGrantingTicket
	advSettingsMap["health_check_fall"] = appResp.AdvancedSettings.HealthCheckFall
	advSettingsMap["health_check_http_host_header"] = appResp.AdvancedSettings.HealthCheckHTTPHostHeader
	advSettingsMap["health_check_http_url"] = appResp.AdvancedSettings.HealthCheckHTTPURL
	advSettingsMap["health_check_http_version"] = appResp.AdvancedSettings.HealthCheckHTTPVersion
	advSettingsMap["health_check_interval"] = appResp.AdvancedSettings.HealthCheckInterval
	advSettingsMap["health_check_rise"] = appResp.AdvancedSettings.HealthCheckRise
	advSettingsMap["health_check_timeout"] = appResp.AdvancedSettings.HealthCheckTimeout
	advSettingsMap["health_check_type"] = client.MapHealthCheckTypeToDescriptive(appResp.AdvancedSettings.HealthCheckType)
	advSettingsMap["hidden_app"] = appResp.AdvancedSettings.HiddenApp
	advSettingsMap["host_key"] = appResp.AdvancedSettings.HostKey
	advSettingsMap["hsts_age"] = appResp.AdvancedSettings.HSTSage
	advSettingsMap["http_only_cookie"] = appResp.AdvancedSettings.HTTPOnlyCookie
	advSettingsMap["https_sslv3"] = appResp.AdvancedSettings.HTTPSSSLV3
	advSettingsMap["idle_close_time_seconds"] = appResp.AdvancedSettings.IdleCloseTimeSeconds
	advSettingsMap["idle_conn_ceil"] = appResp.AdvancedSettings.IdleConnCeil
	advSettingsMap["idle_conn_floor"] = appResp.AdvancedSettings.IdleConnFloor
	advSettingsMap["idle_conn_step"] = appResp.AdvancedSettings.IdleConnStep
	advSettingsMap["idp_idle_expiry"] = appResp.AdvancedSettings.IDPIdleExpiry
	advSettingsMap["idp_max_expiry"] = appResp.AdvancedSettings.IDPMaxExpiry
	advSettingsMap["ignore_bypass_mfa"] = appResp.AdvancedSettings.IgnoreBypassMFA
	advSettingsMap["inject_ajax_javascript"] = appResp.AdvancedSettings.InjectAjaxJavascript
	advSettingsMap["intercept_url"] = appResp.AdvancedSettings.InterceptURL
	advSettingsMap["is_brotli_enabled"] = appResp.AdvancedSettings.IsBrotliEnabled
	advSettingsMap["keepalive_connection_pool"] = appResp.AdvancedSettings.KeepaliveConnectionPool
	advSettingsMap["keepalive_enable"] = appResp.AdvancedSettings.KeepaliveEnable
	advSettingsMap["keepalive_timeout"] = appResp.AdvancedSettings.KeepaliveTimeout
	advSettingsMap["load_balancing_metric"] = appResp.AdvancedSettings.LoadBalancingMetric
	advSettingsMap["logging_enabled"] = appResp.AdvancedSettings.LoggingEnabled
	advSettingsMap["login_timeout"] = appResp.AdvancedSettings.LoginTimeout
	advSettingsMap["login_url"] = appResp.AdvancedSettings.LoginURL
	advSettingsMap["mdc_enable"] = appResp.AdvancedSettings.MDCEnable
	advSettingsMap["mfa"] = appResp.AdvancedSettings.MFA
	advSettingsMap["offload_onpremise_traffic"] = appResp.AdvancedSettings.OffloadOnPremiseTraffic
	advSettingsMap["onramp"] = appResp.AdvancedSettings.Onramp
	advSettingsMap["pass_phrase"] = appResp.AdvancedSettings.PassPhrase
	advSettingsMap["preauth_consent"] = appResp.AdvancedSettings.PreauthConsent
	advSettingsMap["preauth_enforce_url"] = appResp.AdvancedSettings.PreauthEnforceURL
	advSettingsMap["private_key"] = appResp.AdvancedSettings.PrivateKey
	advSettingsMap["remote_spark_audio"] = appResp.AdvancedSettings.RemoteSparkAudio
	advSettingsMap["remote_spark_disk"] = appResp.AdvancedSettings.RemoteSparkDisk
	advSettingsMap["remote_spark_map_clipboard"] = appResp.AdvancedSettings.RemoteSparkMapClipboard
	advSettingsMap["remote_spark_map_disk"] = appResp.AdvancedSettings.RemoteSparkMapDisk
	advSettingsMap["remote_spark_map_printer"] = appResp.AdvancedSettings.RemoteSparkMapPrinter
	advSettingsMap["remote_spark_printer"] = appResp.AdvancedSettings.RemoteSparkPrinter
	advSettingsMap["remote_spark_recording"] = appResp.AdvancedSettings.RemoteSparkRecording
	advSettingsMap["request_body_rewrite"] = appResp.AdvancedSettings.RequestBodyRewrite
	advSettingsMap["request_parameters"] = appResp.AdvancedSettings.RequestParameters
	advSettingsMap["saas_enabled"] = appResp.AdvancedSettings.SaaSEnabled
	advSettingsMap["segmentation_policy_enable"] = appResp.AdvancedSettings.SegmentationPolicyEnable
	advSettingsMap["sentry_restore_form_post"] = appResp.AdvancedSettings.SentryRestoreFormPost
	advSettingsMap["server_cert_validate"] = appResp.AdvancedSettings.ServerCertValidate
	advSettingsMap["server_request_burst"] = appResp.AdvancedSettings.ServerRequestBurst
	advSettingsMap["service_principle_name"] = appResp.AdvancedSettings.ServicePrincipleName
	advSettingsMap["session_sticky"] = appResp.AdvancedSettings.SessionSticky
	advSettingsMap["session_sticky_cookie_maxage"] = appResp.AdvancedSettings.SessionStickyCookieMaxAge
	advSettingsMap["session_sticky_server_cookie"] = appResp.AdvancedSettings.SessionStickyServerCookie
	advSettingsMap["single_host_content_rw"] = appResp.AdvancedSettings.SingleHostContentRW
	advSettingsMap["single_host_cookie_domain"] = appResp.AdvancedSettings.SingleHostCookieDomain
	advSettingsMap["single_host_enable"] = appResp.AdvancedSettings.SingleHostEnable
	advSettingsMap["single_host_fqdn"] = appResp.AdvancedSettings.SingleHostFQDN
	advSettingsMap["single_host_path"] = appResp.AdvancedSettings.SingleHostPath
	advSettingsMap["spdy_enabled"] = appResp.AdvancedSettings.SPDYEnabled
	advSettingsMap["ssh_audit_enabled"] = appResp.AdvancedSettings.SSHAuditEnabled
	advSettingsMap["sso"] = appResp.AdvancedSettings.SSO
	advSettingsMap["user_name"] = appResp.AdvancedSettings.UserName
	advSettingsMap["wapp_auth"] = appResp.AdvancedSettings.WappAuth
	advSettingsMap["x_wapp_pool_enabled"] = appResp.AdvancedSettings.XWappPoolEnabled
	advSettingsMap["x_wapp_pool_size"] = convertStringToInt(appResp.AdvancedSettings.XWappPoolSize)
	advSettingsMap["x_wapp_pool_timeout"] = convertStringToInt(appResp.AdvancedSettings.XWappPoolTimeout)
	advSettingsMap["rdp_keyboard_lang"] = appResp.AdvancedSettings.RDPKeyboardLang
	advSettingsMap["rdp_remote_apps"] = appResp.AdvancedSettings.RDPRemoteApps
	advSettingsMap["rdp_window_color_depth"] = appResp.AdvancedSettings.RDPWindowColorDepth
	advSettingsMap["rdp_window_height"] = appResp.AdvancedSettings.RDPWindowHeight
	advSettingsMap["rdp_window_width"] = appResp.AdvancedSettings.RDPWindowWidth

	// Handle CORS max age
	if appResp.AdvancedSettings.CORSMaxAge != "" {
		if corsAge, err := strconv.Atoi(appResp.AdvancedSettings.CORSMaxAge); err == nil {
			advSettingsMap["cors_max_age"] = corsAge
		}
	}

	// Handle custom headers - now just strings
	if len(appResp.AdvancedSettings.CustomHeaders) > 0 {
		advSettingsMap["custom_headers"] = appResp.AdvancedSettings.CustomHeaders
	}

	// Convert to JSON string
	advSettingsJSON, err := json.Marshal(advSettingsMap)
	if err != nil {
		return diag.Errorf("failed to marshal advanced settings to JSON: %v", err)
	}

	err = d.Set("advanced_settings", string(advSettingsJSON))
	if err != nil {
		return diag.FromErr(err)
	}

	// Create Application struct from response to call methods
	app := client.Application{}
	app.FromResponse(&appResp)

	appAgents, err := app.GetAppAgents(eaaclient)
	if err == nil {
		err = d.Set("agents", appAgents)
		if err != nil {
			return diag.FromErr(err) // Return the error wrapped in a diag.Diagnostic
		}
	}
	if appResp.AuthEnabled == "true" {
		appAuthData, err := app.CreateAppAuthenticationStruct(eaaclient)
		if err == nil {
			err = d.Set("app_authentication", appAuthData)
			if err != nil {
				return diag.FromErr(err) // Return the error wrapped in a diag.Diagnostic
			}
		}
	}

	if appResp.Cert != nil {
		appCertData, err := client.GetCertificate(eaaclient, *appResp.Cert)
		if err == nil {
			err = d.Set("cert", appCertData.Cert)
			if err != nil {
				return diag.FromErr(err)
			}
		}
	}

	aclSrv, err := client.GetACLService(eaaclient, appResp.UUIDURL)
	if err != nil {
		return diag.FromErr(err)
	} else {
		appSvcData, err := aclSrv.CreateAppServiceStruct(eaaclient)
		if err == nil && appSvcData != nil {
			err = d.Set("service", appSvcData)
			if err != nil {
				return diag.FromErr(err) // Return the error wrapped in a diag.Diagnostic
			}
		}
	}

	// Set SAML settings in state as nested blocks
	// Always set saml_settings to ensure it appears in state (empty array if no settings)
	var samlSettings []map[string]interface{}

	if len(appResp.SAMLSettings) > 0 {
		// Convert SAML settings to nested block structure
		for _, samlConfig := range appResp.SAMLSettings {
			samlBlock := make(map[string]interface{})

			// Convert SP block (only fields that exist in schema)
			spBlock := make(map[string]interface{})
			spBlock["entity_id"] = samlConfig.SP.EntityID
			spBlock["acs_url"] = samlConfig.SP.ACSURL
			spBlock["slo_url"] = samlConfig.SP.SLOURL
			spBlock["dst_url"] = samlConfig.SP.DSTURL
			spBlock["resp_bind"] = samlConfig.SP.ReqBind
			spBlock["encr_algo"] = samlConfig.SP.EncrAlgo
			// Note: Other fields like force_auth, req_verify, sign_cert, etc. don't exist in SP schema
			samlBlock["sp"] = []map[string]interface{}{spBlock}

			// Convert IDP block (only fields that exist in schema)
			idpBlock := make(map[string]interface{})
			idpBlock["entity_id"] = samlConfig.IDP.EntityID
			idpBlock["sign_algo"] = samlConfig.IDP.SignAlgo
			if samlConfig.IDP.SignCert != nil {
				idpBlock["sign_cert"] = *samlConfig.IDP.SignCert
			}
			idpBlock["sign_key"] = samlConfig.IDP.SignKey
			idpBlock["self_signed"] = samlConfig.IDP.SelfSigned
			// Note: Other fields like metadata, resp_bind, slo_url, etc. don't exist in IDP schema
			samlBlock["idp"] = []map[string]interface{}{idpBlock}

			// Convert Subject block
			subjectBlock := make(map[string]interface{})
			subjectBlock["fmt"] = samlConfig.Subject.Fmt
			subjectBlock["src"] = samlConfig.Subject.Src
			// Note: val and rule fields don't exist in SAML subject schema
			samlBlock["subject"] = []map[string]interface{}{subjectBlock}

			// Convert Attrmap blocks
			var attrmapBlocks []map[string]interface{}
			for _, attr := range samlConfig.Attrmap {
				attrmapBlock := make(map[string]interface{})
				attrmapBlock["name"] = attr.Name
				attrmapBlock["value"] = attr.Val
				attrmapBlocks = append(attrmapBlocks, attrmapBlock)
			}
			samlBlock["attrmap"] = attrmapBlocks

			samlSettings = append(samlSettings, samlBlock)
		}
	}

	// Always set saml_settings (empty array if no settings)
	err = d.Set("saml_settings", samlSettings)
	if err != nil {
		return diag.FromErr(err)
	}

	// Set WS-Federation settings in state as nested blocks
	// Always set wsfed_settings to ensure it appears in state (empty array if no settings)
	var wsfedSettings []map[string]interface{}

	if len(appResp.WSFEDSettings) > 0 {
		// Convert WS-Federation settings to nested block structure
		for _, wsfedConfig := range appResp.WSFEDSettings {
			wsfedBlock := make(map[string]interface{})

			// SP block
			if wsfedConfig.SP.EntityID != "" || wsfedConfig.SP.SLOURL != "" || wsfedConfig.SP.DSTURL != "" ||
				wsfedConfig.SP.RespBind != "" || wsfedConfig.SP.TokenLife != 0 || wsfedConfig.SP.EncrAlgo != "" {
				spBlock := map[string]interface{}{
					"entity_id":  wsfedConfig.SP.EntityID,
					"slo_url":    wsfedConfig.SP.SLOURL,
					"dst_url":    wsfedConfig.SP.DSTURL,
					"resp_bind":  wsfedConfig.SP.RespBind,
					"token_life": wsfedConfig.SP.TokenLife,
					"encr_algo":  wsfedConfig.SP.EncrAlgo,
				}
				wsfedBlock["sp"] = []map[string]interface{}{spBlock}
			}

			// IDP block
			if wsfedConfig.IDP.EntityID != "" || wsfedConfig.IDP.SignAlgo != "" || wsfedConfig.IDP.SignCert != "" ||
				wsfedConfig.IDP.SignKey != "" || wsfedConfig.IDP.SelfSigned {
				idpBlock := map[string]interface{}{
					"entity_id":   wsfedConfig.IDP.EntityID,
					"sign_algo":   wsfedConfig.IDP.SignAlgo,
					"sign_cert":   wsfedConfig.IDP.SignCert,
					"sign_key":    wsfedConfig.IDP.SignKey,
					"self_signed": wsfedConfig.IDP.SelfSigned,
				}
				wsfedBlock["idp"] = []map[string]interface{}{idpBlock}
			}

			// Subject block
			if wsfedConfig.Subject.Fmt != "" || wsfedConfig.Subject.CustomFmt != "" || wsfedConfig.Subject.Src != "" ||
				wsfedConfig.Subject.Val != "" || wsfedConfig.Subject.Rule != "" {
				subjectBlock := map[string]interface{}{
					"fmt":        wsfedConfig.Subject.Fmt,
					"custom_fmt": wsfedConfig.Subject.CustomFmt,
					"src":        wsfedConfig.Subject.Src,
					"val":        wsfedConfig.Subject.Val,
					"rule":       wsfedConfig.Subject.Rule,
				}
				wsfedBlock["subject"] = []map[string]interface{}{subjectBlock}
			}

			// Attrmap block
			if len(wsfedConfig.Attrmap) > 0 {
				attrmapBlocks := make([]map[string]interface{}, len(wsfedConfig.Attrmap))
				for i, attr := range wsfedConfig.Attrmap {
					attrmapBlocks[i] = map[string]interface{}{
						"name":       attr.Name,
						"fmt":        attr.Fmt,
						"custom_fmt": attr.CustomFmt,
						"val":        attr.Val,
						"src":        attr.Src,
						"rule":       attr.Rule,
					}
				}
				wsfedBlock["attrmap"] = attrmapBlocks
			}

			wsfedSettings = append(wsfedSettings, wsfedBlock)
		}
	}

	// Always set wsfed_settings (empty array if no settings)
	err = d.Set("wsfed_settings", wsfedSettings)
	if err != nil {
		return diag.FromErr(err)
	}

	// Set OIDC settings in state as nested blocks
	var oidcSettings []map[string]interface{}
	if appResp.OIDCSettings != nil {
		oidcBlock := make(map[string]interface{})

		// Convert OIDC endpoints (if they exist in the schema)
		if appResp.OIDCSettings.AuthorizationEndpoint != "" {
			oidcBlock["authorization_endpoint"] = appResp.OIDCSettings.AuthorizationEndpoint
		}
		if appResp.OIDCSettings.TokenEndpoint != "" {
			oidcBlock["token_endpoint"] = appResp.OIDCSettings.TokenEndpoint
		}
		if appResp.OIDCSettings.UserinfoEndpoint != "" {
			oidcBlock["userinfo_endpoint"] = appResp.OIDCSettings.UserinfoEndpoint
		}
		if appResp.OIDCSettings.JWKSURI != "" {
			oidcBlock["jwks_uri"] = appResp.OIDCSettings.JWKSURI
		}
		if appResp.OIDCSettings.DiscoveryURL != "" {
			oidcBlock["discovery_url"] = appResp.OIDCSettings.DiscoveryURL
		}
		if appResp.OIDCSettings.CertsURI != "" {
			oidcBlock["certs_uri"] = appResp.OIDCSettings.CertsURI
		}
		if appResp.OIDCSettings.CheckSessionIframe != "" {
			oidcBlock["check_session_iframe"] = appResp.OIDCSettings.CheckSessionIframe
		}
		if appResp.OIDCSettings.EndSessionEndpoint != "" {
			oidcBlock["end_session_endpoint"] = appResp.OIDCSettings.EndSessionEndpoint
		}
		if appResp.OIDCSettings.OpenIDMetadata != "" {
			oidcBlock["openid_metadata"] = appResp.OIDCSettings.OpenIDMetadata
		}

		// Convert OIDC clients
		if len(appResp.OIDCClients) > 0 {
			var oidcClients []map[string]interface{}
			for _, client := range appResp.OIDCClients {
				clientBlock := make(map[string]interface{})
				clientBlock["client_name"] = client.ClientName
				clientBlock["client_id"] = client.ClientID
				clientBlock["response_type"] = client.ResponseType
				clientBlock["implicit_grant"] = client.ImplicitGrant
				clientBlock["type"] = client.Type
				clientBlock["redirect_uris"] = client.RedirectURIs
				clientBlock["javascript_origins"] = client.JavaScriptOrigins

				// Convert claims
				var claims []map[string]interface{}
				for _, claim := range client.Claims {
					claimBlock := make(map[string]interface{})
					claimBlock["name"] = claim.Name
					claimBlock["scope"] = claim.Scope
					claimBlock["val"] = claim.Val
					claimBlock["src"] = claim.Src
					claimBlock["rule"] = claim.Rule
					claims = append(claims, claimBlock)
				}
				clientBlock["claims"] = claims

				oidcClients = append(oidcClients, clientBlock)
			}
			oidcBlock["oidc_clients"] = oidcClients
		}

		oidcSettings = append(oidcSettings, oidcBlock)
	}

	err = d.Set("oidc_settings", oidcSettings)
	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}

// resourceEaaApplicationUpdate function updates an existing EAA application.
// fetches the application, updates it based on the changed attributes, and deploys the application.
// then calls the read function to ensure the updated data is correctly populated in the schema.

func resourceEaaApplicationUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Set the resource ID
	id := d.Id()
	eaaclient := m.(*client.EaaClient)

	// Advanced settings validation is now handled at plan time via CustomizeDiff

	var appResp client.Application

	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, id)

	getResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
	if err != nil {
		return diag.FromErr(err)
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		_, _ = client.FormatErrorResponse(getResp)
		getAppErrMsg := client.ErrGetAppFailed
		return diag.FromErr(getAppErrMsg)
	}

	// Store the update request for later use after IDP assignment
	appUpdateReq := client.ApplicationUpdateRequest{}
	appUpdateReq.Application = appResp
	err = appUpdateReq.UpdateAppRequestFromSchema(ctx, d, eaaclient)
	if err != nil {
		return diag.FromErr(err)
	}

	currAgents, err := appResp.GetAppAgents(eaaclient)
	if err == nil {
		if agentsRaw, ok := d.GetOk("agents"); ok {
			agentList := agentsRaw.([]interface{})
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
				agents.AppId = id
				agents.AgentNames = append(agents.AgentNames, agentsToAssign...)
				err := agents.AssignAgents(ctx, eaaclient)
				if err != nil {
					return diag.FromErr(err)
				}
			}
			if len(agentsToUnassign) > 0 {
				var agents client.AssignAgents
				agents.AppId = id
				agents.AgentNames = append(agents.AgentNames, agentsToUnassign...)

				err := agents.UnAssignAgents(ctx, eaaclient)
				if err != nil {
					return diag.FromErr(err)
				}
			}
		}
	}
	if d.HasChange("app_authentication") {
		auth_enabled := "false"

		if aE, ok := d.GetOk("auth_enabled"); ok {
			auth_enabled = aE.(string)
		}

		if auth_enabled == "true" {
			if appAuth, ok := d.GetOk("app_authentication"); ok {
				app_uuid_url := id
				appIDPMembership, err := appResp.GetAppIdpMembership(eaaclient)
				if err != nil {
					return diag.FromErr(err)
				}
				if appIDPMembership != nil {
					appIdp := client.AppIdp{
						App: app_uuid_url,
						IDP: appIDPMembership.UUIDURL,
					}
					err = appIdp.UnAssignIDP(eaaclient)
					if err != nil {
						eaaclient.Logger.Error("idp unassign error err ", err)
						return diag.FromErr(err)
					}
				}
				appAuthList := appAuth.([]interface{})
				if appAuthList == nil {
					return diag.FromErr(ErrInvalidData)
				}
				if len(appAuthList) > 0 {
					appAuthenticationMap := appAuthList[0].(map[string]interface{})
					if appAuthenticationMap == nil {
						eaaclient.Logger.Error("invalid authentication data")
						return diag.FromErr(ErrInvalidData)
					}

					// Check if app_idp key is present
					if app_idp_name, ok := appAuthenticationMap["app_idp"].(string); ok {
						idpData, err := client.GetIdpWithName(ctx, eaaclient, app_idp_name)
						if err != nil || idpData == nil {
							eaaclient.Logger.Error("get idp with name error, err ", err)
							return diag.FromErr(err)
						}

						eaaclient.Logger.Debug("Starting IDP assignment in UPDATE flow")
						eaaclient.Logger.Debug("Assigning IDP to application in UPDATE")
						eaaclient.Logger.Debug("app_uuid_url", "value", app_uuid_url)
						eaaclient.Logger.Debug("idpData.UUIDURL", "value", idpData.UUIDURL)

						appIdp := client.AppIdp{
							App: app_uuid_url,
							IDP: idpData.UUIDURL,
						}
						err = appIdp.AssignIDP(eaaclient)
						if err != nil {
							eaaclient.Logger.Error("IDP assign error in UPDATE", "error", err)
							return diag.FromErr(err)
						}
						eaaclient.Logger.Debug("IDP assigned successfully in UPDATE", "app_name", appResp.Name, "idp", app_idp_name)

						// check if app_directories are present
						if appDirs, ok := appAuthenticationMap["app_directories"]; ok {
							eaaclient.Logger.Debug("Starting directory assignment in UPDATE...")
							err := idpData.AssignIdpDirectories(ctx, appDirs, app_uuid_url, eaaclient)
							if err != nil {
								eaaclient.Logger.Error("Directory assignment error in UPDATE", "error", err)
								return diag.FromErr(err)
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
		services := d.Get("service").([]interface{})

		if len(services) > 0 {
			app_uuid_url := appResp.UUIDURL
			appSrv, err := client.GetACLService(eaaclient, app_uuid_url)
			if err != nil {
				return diag.FromErr(err)
			}

			aclSrv, err := client.ExtractACLService(ctx, d, eaaclient)
			if err != nil {
				return diag.FromErr(err)
			}

			if appSrv.Status != aclSrv.Status {
				appSrv.Status = aclSrv.Status
				err := appSrv.EnableService(eaaclient)
				if err != nil {
					return diag.FromErr(err)
				}
			}
			if d.HasChange("service.0.access_rule") {
				// Fetch existing rules
				existingACLResponse, err := client.GetAccessControlRules(eaaclient, appSrv.UUIDURL)
				if err != nil {
					return diag.FromErr(err)
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
						if err := existingRule.DeleteAccessRule(ctx, eaaclient, appSrv.UUIDURL); err != nil {
							return diag.FromErr(err)
						}
					}
				}

				// Handle creations and modifications
				for name, newRule := range newRulesMap {
					if existingRule, exists := existingRulesMap[name]; exists {
						if !existingRule.IsEqual(newRule) {
							newRule.UUID_URL = existingRule.UUID_URL
							if err := newRule.ModifyAccessRule(ctx, eaaclient, appSrv.UUIDURL); err != nil {
								return diag.FromErr(err)
							}
						}
					} else {
						// Create new rule
						if err := newRule.CreateAccessRule(ctx, eaaclient, appSrv.UUIDURL); err != nil {
							return diag.FromErr(err)
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
		return diag.FromErr(err)
	}
	eaaclient.Logger.Debug("PUT call completed successfully in UPDATE flow")

	// Add delay before deploy in UPDATE flow to ensure all operations are complete
	eaaclient.Logger.Info("waiting before deploy in UPDATE flow...")

	err = appUpdateReq.DeployApplication(eaaclient)
	if err != nil {
		return diag.FromErr(err)
	}

	return resourceEaaApplicationRead(ctx, d, m)
}

// resourceEaaApplicationDelete function deletes an existing EAA application.
// sends a delete request to the EAA client to remove the application.
func resourceEaaApplicationDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Read the resource ID from d
	id := d.Id()
	eaaclient := m.(*client.EaaClient)
	var appResp client.ApplicationDataModel

	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, id)
	getResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
	if err != nil {
		return diag.FromErr(err)
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		_, _ = client.FormatErrorResponse(getResp)
		getAppErrMsg := client.ErrGetAppFailed
		return diag.FromErr(getAppErrMsg)
	}
	err = appResp.DeleteApplication(eaaclient)
	if err != nil {
		return diag.FromErr(err)
	}

	// Set the resource ID to mark it as deleted
	d.SetId("")

	return nil
}

// convertStringToInt converts string to int, returns 0 if conversion fails
func convertStringToInt(value string) int {
	if value == "" {
		return 0
	}
	if i, err := strconv.Atoi(value); err == nil {
		return i
	}
	return 0
}

// convertStringPointerToString converts *string to string, returns null string for nil
func convertStringPointerToString(value *string) string {
	if value == nil {
		return "null"
	}
	return *value
}

// validateAppAuthBasedOnTypeAndProfile validates app_auth based on app_type and app_profile
func validateAppAuthBasedOnTypeAndProfile(v interface{}, k string) (ws []string, errors []error) {
	// This function will be called from the resource validation context
	// We need to get the resource data to check app_type and app_profile
	// For now, we'll do basic validation and the detailed validation will be done in the resource

	value, ok := v.(string)
	if !ok {
		errors = append(errors, client.ErrExpectedString)
		return
	}

	// Basic validation - detailed validation will be done in the resource
	validValues := []string{"none", "SAML2.0", "oidc", "OpenID Connect 1.0", "wsfed", "WS-Federation", "kerberos", "basic", "NTLMv1", "NTLMv2"}

	isValid := false
	for _, validValue := range validValues {
		if value == validValue {
			isValid = true
			break
		}
	}

	if !isValid {
		errors = append(errors, client.ErrInvalidAppAuthValue)
		return
	}

	return
}

// validateAdvancedSettingsWithAppTypeAndProfile validates advanced_settings with app_type and app_profile context
func validateAdvancedSettingsWithAppTypeAndProfile(d *schema.ResourceData) error {
	// Create a null logger for schema validation (this function doesn't have access to meta)
	logger := hclog.NewNullLogger()

	// Get app_type and app_profile first
	appType := ""
	appProfile := ""

	if at, ok := d.GetOk("app_type"); ok {
		appType = at.(string)
	}

	if ap, ok := d.GetOk("app_profile"); ok {
		appProfile = ap.(string)
	}

	// For bookmark and saas, advanced_settings should not be allowed at all
	// These app types should use resource-level configuration instead
	if appType == "bookmark" || appType == "saas" {
		advSettings, ok := d.GetOk("advanced_settings")
		if ok {
			advSettingsStr, ok := advSettings.(string)
			if ok && advSettingsStr != "" && advSettingsStr != "{}" {
				return client.ErrAdvancedSettingsNotAllowedForAppType
			}
		}
		return nil
	}

	// Get advanced_settings for other app types
	advSettings, ok := d.GetOk("advanced_settings")
	if !ok {
		return nil // No advanced settings provided
	}

	advSettingsStr, ok := advSettings.(string)
	if !ok {
		return client.ErrAdvancedSettingsNotString
	}

	// If empty, it's valid (will use defaults)
	if advSettingsStr == "" || advSettingsStr == "{}" {
		return nil
	}

	// Parse the JSON
	var settings map[string]interface{}
	if err := json.Unmarshal([]byte(advSettingsStr), &settings); err != nil {
		return client.ErrAdvancedSettingsInvalidJSON
	}

	// Validate app_auth if present
	if appAuth, exists := settings["app_auth"]; exists {
		if appAuthStr, ok := appAuth.(string); ok {
			if err := validateAppAuthForTypeAndProfile(appAuthStr, appType, appProfile); err != nil {
				return err
			}
		}
	}

	// Validate health check settings if present (skip for tunnel apps)
	if appType != "tunnel" {
		logger.Debug("Validating health check for app_type: %s", appType)
		if err := validateHealthCheckConfiguration(settings, appType, appProfile, logger); err != nil {
			logger.Error("Health check validation failed for app_type %s: %v", appType, err)
			return err // Return the specific error instead of generic one
		}
	} else {
		logger.Debug("Skipping health check validation for tunnel app")
	}

	// Validate server load balancing settings if present
	if err := validateServerLoadBalancingConfiguration(settings, appType, appProfile, logger); err != nil {
		return client.ErrServerLoadBalancingValidationFailed
	}

	// Validate related applications settings if present
	if err := validateRelatedApplications(settings, appType, appProfile, logger); err != nil {
		return client.ErrRelatedApplicationsNotSupportedForProfile
	}

	// Note: Enterprise connectivity, miscellaneous parameters, RDP configuration, and tunnel client parameters
	// are now validated by the comprehensive generic validation system in ValidateAdvancedSettings()

	// Validate TLS Suite configuration restrictions
	if err := validateTLSSuiteRestrictions(appType, appProfile, settings); err != nil {
		return client.ErrTLSSuiteRestrictionsValidationFailed
	}

	// Note: TLS custom suite name validation is skipped in schema validation
	// as this function doesn't have access to the client/meta for API calls
	// This validation is performed in plan-time validation instead

	return nil
}

// validateAppAuthForTypeAndProfile validates app_auth based on app_type and app_profile
func validateAppAuthForTypeAndProfile(appAuth, appType, appProfile string) error {
	// First validate the app_auth value itself
	if err := validateAppAuthValue(appAuth); err != nil {
		return err
	}

	// Apply validation rules based on the requirements
	switch {
	case appType == "enterprise" && appProfile == "ssh":
		// app_auth is disabled - field should not be present in advanced_settings
		return client.ErrAppAuthDisabledForEnterpriseSSH

	case appType == "saas":
		// app_auth should not be present in advanced_settings for SaaS apps
		// Authentication is handled at resource level using boolean flags (saml: true, oidc: true, wsfed: true)
		return client.ErrAppAuthNotAllowedForSaaS

	case appType == "bookmark":
		// app_auth should not be present in advanced_settings - it's set at resource level
		return client.ErrAppAuthNotAllowedForBookmark

	case appType == "tunnel":
		// app_auth should not be present in advanced_settings - it's set at resource level as "tcp"
		return client.ErrAppAuthNotAllowedForTunnel

	case appType == "enterprise" && appProfile == "vnc":
		// app_auth is disabled - field should not be present in advanced_settings
		return client.ErrAppAuthDisabledForEnterpriseVNC
	}

	return nil
}

// validateAuthenticationMethodsForAppType validates that authentication method flags are appropriate for the app type
func validateAuthenticationMethodsForAppType(d *schema.ResourceData) error {
	// Get app_type for validation
	appType := ""
	if at, ok := d.GetOk("app_type"); ok {
		appType = at.(string)
	}

	// Check if tunnel app is trying to use advanced authentication methods
	if appType == "tunnel" {
		// Check if SAML is enabled
		if saml, ok := d.GetOk("saml"); ok && saml.(bool) {
			return fmt.Errorf("saml=true is not allowed for tunnel apps. Tunnel apps use basic authentication")
		}

		// Check if OIDC is enabled
		if oidc, ok := d.GetOk("oidc"); ok && oidc.(bool) {
			return fmt.Errorf("oidc=true is not allowed for tunnel apps. Tunnel apps use basic authentication")
		}

		// Check if WSFED is enabled
		if wsfed, ok := d.GetOk("wsfed"); ok && wsfed.(bool) {
			return fmt.Errorf("wsfed=true is not allowed for tunnel apps. Tunnel apps use basic authentication")
		}
	}

	// Check if bookmark app is trying to use advanced authentication methods
	if appType == "bookmark" {
		// Check if SAML is enabled
		if saml, ok := d.GetOk("saml"); ok && saml.(bool) {
			return fmt.Errorf("saml=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
		}

		// Check if OIDC is enabled
		if oidc, ok := d.GetOk("oidc"); ok && oidc.(bool) {
			return fmt.Errorf("oidc=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
		}

		// Check if WSFED is enabled
		if wsfed, ok := d.GetOk("wsfed"); ok && wsfed.(bool) {
			return fmt.Errorf("wsfed=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
		}
	}

	return nil
}

// validateAuthenticationMethodsForAppTypeWithDiff validates authentication methods using ResourceDiff
func validateAuthenticationMethodsForAppTypeWithDiff(d *schema.ResourceDiff) error {
	// Get app_type for validation
	appType := ""
	if at, ok := d.GetOk("app_type"); ok {
		appType = at.(string)
	}

	// Debug logging
	fmt.Printf("DEBUG: validateAuthenticationMethodsForAppTypeWithDiff called for app_type=%s\n", appType)

	// Check if tunnel app is trying to use advanced authentication methods
	if appType == "tunnel" {
		// Check if SAML is enabled
		if saml, ok := d.GetOk("saml"); ok {
			if samlBool, ok := saml.(bool); ok && samlBool {
				fmt.Printf("DEBUG: Tunnel app with SAML detected, returning error\n")
				return client.ErrTunnelAppSAMLNotAllowed
			}
		}

		// Check if OIDC is enabled
		if oidc, ok := d.GetOk("oidc"); ok {
			if oidcBool, ok := oidc.(bool); ok && oidcBool {
				return client.ErrTunnelAppOIDCNotAllowed
			}
		}

		// Check if WSFED is enabled
		if wsfed, ok := d.GetOk("wsfed"); ok {
			if wsfedBool, ok := wsfed.(bool); ok && wsfedBool {
				return client.ErrTunnelAppWSFEDNotAllowed
			}
		}
	}

	// Check if bookmark app is trying to use advanced authentication methods
	if appType == "bookmark" {
		// Check if SAML is enabled
		if saml, ok := d.GetOk("saml"); ok {
			if samlBool, ok := saml.(bool); ok && samlBool {
				return client.ErrBookmarkAppSAMLNotAllowed
			}
		}

		// Check if OIDC is enabled
		if oidc, ok := d.GetOk("oidc"); ok {
			if oidcBool, ok := oidc.(bool); ok && oidcBool {
				return client.ErrBookmarkAppOIDCNotAllowed
			}
		}

		// Check if WSFED is enabled
		if wsfed, ok := d.GetOk("wsfed"); ok {
			if wsfedBool, ok := wsfed.(bool); ok && wsfedBool {
				return client.ErrBookmarkAppWSFEDNotAllowed
			}
		}
	}

	return nil
}

// validateTunnelAppAdvancedSettings validates that tunnel apps only use allowed parameter categories
func validateTunnelAppAdvancedSettings(settings map[string]interface{}, logger hclog.Logger) error {
	logger.Debug("validateTunnelAppAdvancedSettings called for tunnel app")

	// Define allowed parameter categories for tunnel apps
	allowedCategories := map[string][]string{
		// Server Load Balancing Parameters
		"server_load_balancing": {
			"load_balancing_metric",
			"session_sticky",
			"session_sticky_cookie_maxage",
			"session_sticky_server_cookie",
			"refresh_sticky_cookie",
			"tcp_optimization",
		},
		// Enterprise Connectivity Parameters
		"enterprise_connectivity": {
			"idle_conn_floor",
			"idle_conn_ceil",
			"idle_conn_step",
			"max_conn_floor",
			"max_conn_ceil",
			"max_conn_step",
			"conn_retry_interval",
			"conn_retry_max_attempts",
			"conn_retry_max_interval",
		},
		// Tunnel Client Parameters (tunnel-specific)
		"tunnel_client_parameters": {
			"domain_exception_list",
			"acceleration",
			"force_ip_route",
			"x_wapp_pool_enabled",
			"x_wapp_pool_size",
			"x_wapp_pool_timeout",
			"x_wapp_read_timeout",
		},
		// Health Check Parameters (tunnel apps only support TCP)
		"health_check": {
			"health_check_type",
			"health_check_rise",
			"health_check_fall",
			"health_check_timeout",
			"health_check_interval",
		},
		// Basic Configuration Parameters
		"basic_config": {
			"is_ssl_verification_enabled",
			"ip_access_allow",
			"websocket_enabled",
			"wildcard_internal_hostname",
		},
	}

	// Create a map of all allowed fields
	allowedFields := make(map[string]bool)
	for _, fields := range allowedCategories {
		for _, field := range fields {
			allowedFields[field] = true
		}
	}

	// Check each field in the settings
	var blockedFields []string
	for fieldName := range settings {
		if !allowedFields[fieldName] {
			// Determine which category this field belongs to (for better error message)
			category := "unknown"
			if isAuthField(fieldName) {
				category = "authentication"
			} else if isCORSField(fieldName) {
				category = "CORS"
			} else if isTLSField(fieldName) {
				category = "TLS Suite"
			} else if isMiscField(fieldName) {
				category = "miscellaneous"
			} else if isRDPField(fieldName) {
				category = "RDP configuration"
			}

			blockedFields = append(blockedFields, fmt.Sprintf("'%s' (%s parameters)", fieldName, category))
		}
	}

	// If there are blocked fields, return an error
	if len(blockedFields) > 0 {
		errorMsg := fmt.Sprintf("Tunnel apps only support Server Load Balancing, Enterprise Connectivity, Tunnel Client Parameters, Health Check, and Basic Configuration parameters. The following fields are not allowed: %s",
			strings.Join(blockedFields, ", "))
		logger.Error("Blocked fields detected for tunnel app: %s", errorMsg)
		return fmt.Errorf(errorMsg)
	}

	logger.Debug("All fields in tunnel app advanced_settings are allowed")
	return nil
}

// Helper functions to categorize fields
func isAuthField(fieldName string) bool {
	authFields := []string{
		"login_url", "logout_url", "wapp_auth", "app_auth", "intercept_url",
		"form_post_url", "form_post_attributes", "app_client_cert_auth",
		"app_cookie_domain", "jwt_issuers", "jwt_audience", "jwt_grace_period",
		"jwt_return_option", "jwt_return_url", "jwt_username", "app_auth_domain",
		"service_principle_name", "keytab", "kerberos_negotiate_once",
		"forward_ticket_granting_ticket", "http_only_cookie", "disable_user_agent_check",
		"preauth_consent", "sentry_redirect_401",
	}
	for _, field := range authFields {
		if fieldName == field {
			return true
		}
	}
	return false
}

func isCORSField(fieldName string) bool {
	corsFields := []string{
		"allow_cors", "cors_origin_list", "cors_header_list", "cors_method_list",
		"cors_support_credential", "cors_max_age",
	}
	for _, field := range corsFields {
		if fieldName == field {
			return true
		}
	}
	return false
}

func isTLSField(fieldName string) bool {
	tlsFields := []string{
		"tlsSuiteType", "tls_suite_name", "tls_cipher_suite",
	}
	for _, field := range tlsFields {
		if fieldName == field {
			return true
		}
	}
	return false
}

func isMiscField(fieldName string) bool {
	miscFields := []string{
		"proxy_buffer_size_kb", "ssh_audit_enabled", "hidden_app", "logging_enabled",
		"offload_onpremise_traffic", "saas_enabled", "segmentation_policy_enable",
		"sentry_restore_form_post", "sla_object_url", "user_name", "custom_headers",
		"inject_ajax_javascript", "internal_host_port", "login_timeout", "mdc_enable",
		"onramp", "pass_phrase", "private_key", "proxy_disable_clipboard", "rate_limit",
		"request_body_rewrite", "request_parameters",
	}
	for _, field := range miscFields {
		if fieldName == field {
			return true
		}
	}
	return false
}

func isRDPField(fieldName string) bool {
	rdpFields := []string{
		"rdp_audio_redirection", "rdp_clipboard_redirection", "rdp_disk_redirection",
		"rdp_port_redirection", "rdp_printer_redirection", "rdp_smart_card_redirection",
		"rdp_usb_redirection", "rdp_webcam_redirection",
	}
	for _, field := range rdpFields {
		if fieldName == field {
			return true
		}
	}
	return false
}

// validateAppAuthConflictsWithResourceLevelAuth validates app_auth conflicts with resource-level auth settings
func validateAppAuthConflictsWithResourceLevelAuth(settings map[string]interface{}, diff *schema.ResourceDiff, logger hclog.Logger) error {
	// Check if app_auth is present in advanced_settings
	appAuth, exists := settings["app_auth"]
	if !exists {
		logger.Debug("No app_auth field found, skipping conflict validation")
		return nil
	}

	appAuthStr, ok := appAuth.(string)
	if !ok {
		logger.Debug("app_auth is not a string, skipping conflict validation")
		return nil
	}

	logger.Debug("Validating app_auth conflicts for value: %s", appAuthStr)

	// Check for SAML/OIDC/WSFED conflicts - when these are enabled, app_auth must be "none"
	if appAuthStr != "none" {
		// Check if SAML is enabled
		if saml, ok := diff.GetOk("saml"); ok && saml.(bool) {
			return fmt.Errorf("when saml is enabled (saml=true), app_auth must be set to 'none' in advanced_settings, got '%s'", appAuthStr)
		}

		// Check if OIDC is enabled
		if oidc, ok := diff.GetOk("oidc"); ok && oidc.(bool) {
			return fmt.Errorf("when oidc is enabled (oidc=true), app_auth must be set to 'none' in advanced_settings, got '%s'", appAuthStr)
		}

		// Check if WSFED is enabled
		if wsfed, ok := diff.GetOk("wsfed"); ok && wsfed.(bool) {
			return fmt.Errorf("when wsfed is enabled (wsfed=true), app_auth must be set to 'none' in advanced_settings, got '%s'", appAuthStr)
		}
	}

	// Additional validation: specific conflicts with SAML
	if saml, ok := diff.GetOk("saml"); ok && saml.(bool) {
		// When SAML is enabled, app_auth cannot be kerberos, NTLMv1, or NTLMv2
		conflictingValues := []string{"kerberos", "NTLMv1", "NTLMv2"}
		for _, conflictingValue := range conflictingValues {
			if appAuthStr == conflictingValue {
				return fmt.Errorf("when saml is enabled (saml=true), app_auth cannot be '%s' in advanced_settings. Use 'none' instead", conflictingValue)
			}
		}
	}

	logger.Debug("App auth conflict validation passed")
	return nil
}

// validateAppAuthWithResourceData validates app_auth with access to resource data for SAML/OIDC/WSFED conflicts
func validateAppAuthWithResourceData(appAuth string, d *schema.ResourceData) error {
	// First validate the app_auth value itself
	if err := validateAppAuthValue(appAuth); err != nil {
		return err
	}

	// Get app_type for tunnel app validation
	appType := ""
	if at, ok := d.GetOk("app_type"); ok {
		appType = at.(string)
	}

	// Check if tunnel app is trying to use advanced authentication methods
	if appType == "tunnel" {
		// Check if SAML is enabled
		if saml, ok := d.GetOk("saml"); ok && saml.(bool) {
			return fmt.Errorf("saml=true is not allowed for tunnel apps. Tunnel apps use basic authentication")
		}

		// Check if OIDC is enabled
		if oidc, ok := d.GetOk("oidc"); ok && oidc.(bool) {
			return fmt.Errorf("oidc=true is not allowed for tunnel apps. Tunnel apps use basic authentication")
		}

		// Check if WSFED is enabled
		if wsfed, ok := d.GetOk("wsfed"); ok && wsfed.(bool) {
			return fmt.Errorf("wsfed=true is not allowed for tunnel apps. Tunnel apps use basic authentication")
		}
	}

	// Check if bookmark app is trying to use advanced authentication methods
	if appType == "bookmark" {
		// Check if SAML is enabled
		if saml, ok := d.GetOk("saml"); ok && saml.(bool) {
			return fmt.Errorf("saml=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
		}

		// Check if OIDC is enabled
		if oidc, ok := d.GetOk("oidc"); ok && oidc.(bool) {
			return fmt.Errorf("oidc=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
		}

		// Check if WSFED is enabled
		if wsfed, ok := d.GetOk("wsfed"); ok && wsfed.(bool) {
			return fmt.Errorf("wsfed=true is not allowed for bookmark apps. Bookmark apps use basic authentication")
		}
	}

	// Check for SAML/OIDC/WSFED conflicts - when these are enabled, app_auth must be "none"
	if appAuth != "none" {
		// Check if SAML is enabled
		if saml, ok := d.GetOk("saml"); ok && saml.(bool) {
			return fmt.Errorf("when saml is enabled (saml=true), app_auth must be set to 'none' in advanced_settings, got '%s'", appAuth)
		}

		// Check if OIDC is enabled
		if oidc, ok := d.GetOk("oidc"); ok && oidc.(bool) {
			return fmt.Errorf("when oidc is enabled (oidc=true), app_auth must be set to 'none' in advanced_settings, got '%s'", appAuth)
		}

		// Check if WSFED is enabled
		if wsfed, ok := d.GetOk("wsfed"); ok && wsfed.(bool) {
			return fmt.Errorf("when wsfed is enabled (wsfed=true), app_auth must be set to 'none' in advanced_settings, got '%s'", appAuth)
		}
	}

	// Additional validation: specific conflicts with SAML
	if saml, ok := d.GetOk("saml"); ok && saml.(bool) {
		// When SAML is enabled, app_auth cannot be kerberos, NTLMv1, or NTLMv2
		conflictingValues := []string{"kerberos", "NTLMv1", "NTLMv2"}
		for _, conflictingValue := range conflictingValues {
			if appAuth == conflictingValue {
				return fmt.Errorf("when saml is enabled (saml=true), app_auth cannot be '%s' in advanced_settings. Use 'none' instead", conflictingValue)
			}
		}
	}

	// Get app_profile for additional validation
	appProfile := ""

	if at, ok := d.GetOk("app_type"); ok {
		appType = at.(string)
	}

	if ap, ok := d.GetOk("app_profile"); ok {
		appProfile = ap.(string)
	}

	// Apply validation rules based on the requirements
	switch {
	case appType == "enterprise" && appProfile == "ssh":
		// app_auth is disabled - field should not be present in advanced_settings
		return client.ErrAppAuthDisabledForEnterpriseSSH

	case appType == "saas":
		// app_auth should not be present in advanced_settings for SaaS apps
		// Authentication is handled at resource level using boolean flags (saml: true, oidc: true, wsfed: true)
		return client.ErrAppAuthNotAllowedForSaaS

	case appType == "bookmark":
		// app_auth should not be present in advanced_settings - it's set at resource level
		return client.ErrAppAuthNotAllowedForBookmark

	case appType == "tunnel":
		// app_auth should not be present in advanced_settings - it's set at resource level as "tcp"
		return client.ErrAppAuthNotAllowedForTunnel

	case appType == "enterprise" && appProfile == "vnc":
		// app_auth is disabled - field should not be present in advanced_settings
		return client.ErrAppAuthDisabledForEnterpriseVNC
	}

	return nil
}

// validateAppAuthValue validates app_auth field values
func validateAppAuthValue(appAuth string) error {
	// Valid values for app_auth based on documentation
	validValues := []string{"none", "kerberos", "basic", "NTLMv1", "NTLMv2", "SAML2.0", "wsfed", "oidc", "OpenID Connect 1.0"}

	isValid := false
	for _, validValue := range validValues {
		if appAuth == validValue {
			isValid = true
			break
		}
	}

	if !isValid {
		return client.ErrInvalidAppAuthValue
	}

	return nil
}

// validateWappAuthValue validates wapp_auth field values
func validateWappAuthValue(wappAuth string) error {
	// Valid values for wapp_auth based on documentation and server validation
	validValues := []string{"form", "basic", "basic_cookie", "jwt", "certonly"}

	isValid := false
	for _, validValue := range validValues {
		if wappAuth == validValue {
			isValid = true
			break
		}
	}

	if !isValid {
		return client.ErrInvalidWappAuthValue
	}

	return nil
}

// Note: validateWappAuthFieldConflicts is now handled by validateWappAuthFieldConflictsGeneric in advanced_settings_conflict_validation.go

// validateTLSSuiteRestrictions validates TLS Suite configuration restrictions based on app_type and app_profile
func validateTLSSuiteRestrictions(appType, appProfile string, settings map[string]interface{}) error {
	// Define TLS Suite fields
	tlsSuiteFields := []string{
		"tlsSuiteType", "tls_suite_name", "tls_cipher_suite",
	}

	// Check if any TLS Suite fields are present
	hasTLSSuiteFields := false
	for _, field := range tlsSuiteFields {
		if _, exists := settings[field]; exists {
			hasTLSSuiteFields = true
			break
		}
	}

	// If no TLS Suite fields are present, no validation needed
	if !hasTLSSuiteFields {
		return nil
	}

	// TLS Suite is NOT AVAILABLE for Tunnel, Bookmark, or SaaS app_types
	if appType == "tunnel" || appType == "bookmark" || appType == "saas" {
		return client.ErrTLSSuiteNotAvailableForAppType
	}

	// TLS Suite is NOT AVAILABLE for SMB app_profile (regardless of app_type)
	if appProfile == "smb" {
		return client.ErrTLSSuiteNotAvailableForSMBProfile
	}

	// TLS Suite is AVAILABLE for enterprise app_type with appropriate app_profiles
	if appType == "enterprise" {
		validProfiles := []string{"http", "sharepoint", "jira", "jenkins", "confluence", "rdp", "vnc", "ssh"}
		isValidProfile := false
		for _, validProfile := range validProfiles {
			if appProfile == validProfile {
				isValidProfile = true
				break
			}
		}

		if !isValidProfile {
			return client.ErrTLSSuiteNotAvailableForEnterpriseProfile
		}
	}

	return nil
}

// validateTLSCustomSuiteName validates that when tlsSuiteType = 2 (CUSTOM), tls_suite_name must be a valid cipher suite
func validateTLSCustomSuiteName(settings map[string]interface{}, validCipherSuites []string) error {
	// Check if tlsSuiteType is present and equals 2 (CUSTOM)
	tlsSuiteType, exists := settings["tlsSuiteType"]
	if !exists {
		return nil // No TLS Suite Type to validate
	}

	tlsSuiteTypeNum, ok := tlsSuiteType.(float64)
	if !ok {
		return nil // Invalid TLS Suite Type
	}

	// Only validate when tlsSuiteType = 2 (CUSTOM)
	if tlsSuiteTypeNum != 2 {
		return nil
	}

	// Get tls_suite_name
	tlsSuiteName, exists := settings["tls_suite_name"]
	if !exists {
		return client.ErrTLSSuiteNameRequired
	}

	tlsSuiteNameStr, ok := tlsSuiteName.(string)
	if !ok {
		return client.ErrTLSSuiteNameNotString
	}

	// Check if the provided tls_suite_name is valid
	isValid := false
	for _, validSuite := range validCipherSuites {
		if tlsSuiteNameStr == validSuite {
			isValid = true
			break
		}
	}

	if !isValid {
		return client.ErrTLSSuiteNameInvalid
	}

	return nil
}

// validateAdvancedSettingsJSON validates that advanced_settings is valid JSON
func validateAdvancedSettingsJSON(i interface{}, k string) ([]string, []error) {
	var warnings []string
	var errors []error

	// Get the advanced_settings value
	advancedSettingsStr, ok := i.(string)
	if !ok {
		errors = append(errors, client.ErrAdvancedSettingsNotString)
		return warnings, errors
	}

	// If empty, it's valid (will use defaults)
	if advancedSettingsStr == "" || advancedSettingsStr == "{}" {
		return warnings, errors
	}

	// Parse the JSON to validate it's valid
	var settings map[string]interface{}
	if err := json.Unmarshal([]byte(advancedSettingsStr), &settings); err != nil {
		errors = append(errors, client.ErrAdvancedSettingsInvalidJSON)
		return warnings, errors
	}

	// For now, we can't access app_type from ValidateFunc
	// This is a limitation of the Terraform SDK
	// We'll need to use a different approach

	return warnings, errors
}
