package eaaprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	ErrInvalidData = errors.New("invalid data in schema")
)

// jsonStringAdvancedSettingsKeys are advanced_settings fields stored as JSON-encoded strings.
// Their values are compared semantically (ignoring key order and whitespace) to avoid
// perpetual diffs caused by jsonencode (alphabetical keys) vs json.Marshal (struct order).
var jsonStringAdvancedSettingsKeys = map[string]bool{
	"custom_headers":       true,
	"form_post_attributes": true,
	"rdp_remote_apps":      true,
}

// serversSetHash hashes a "servers" element on its user-meaningful fields only.
// orig_tls is intentionally excluded: it is Optional+Computed (derived by the API
// from origin_protocol), so including it would make an unset config value hash
// differently from the API-populated state value and reintroduce a perpetual diff.
func serversSetHash(v interface{}) int {
	m, ok := v.(map[string]interface{})
	if !ok {
		return 0
	}
	host, _ := m["origin_host"].(string)         //nolint:errcheck // zero-value is safe for hashing
	port, _ := m["origin_port"].(int)            //nolint:errcheck // zero-value is safe for hashing
	protocol, _ := m["origin_protocol"].(string) //nolint:errcheck // zero-value is safe for hashing
	return schema.HashString(fmt.Sprintf("%s-%d-%s", host, port, protocol))
}

// suppressServerComputedAdvSettingsKey suppresses plan diffs for:
//  1. API-auto-populated keys (e.g. edge_cookie_key) the user never configured.
//  2. JSON-string fields where only key-order or whitespace differs.
func suppressServerComputedAdvSettingsKey(k, old, newStr string, _ *schema.ResourceData) bool {
	parts := strings.SplitN(k, ".", 2)
	if len(parts) != 2 || parts[1] == "%" {
		return false
	}
	key := parts[1]
	if serverComputedAdvancedSettingsKeys[key] && newStr == "" {
		return true
	}
	if jsonStringAdvancedSettingsKeys[key] {
		return jsonSemanticEqual(old, newStr)
	}
	return false
}

// jsonSemanticEqual returns true when a and b represent the same JSON value,
// ignoring key ordering and insignificant whitespace.
func jsonSemanticEqual(a, b string) bool {
	if a == b {
		return true
	}
	var ja, jb interface{}
	if err := json.Unmarshal([]byte(a), &ja); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(b), &jb); err != nil {
		return false
	}
	return reflect.DeepEqual(ja, jb)
}

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
				Computed: true,
			},
			"host": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"bookmark_url": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"tls_suite_name": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},

			"domain": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"domain_suffix": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"origin_host": {
				Type:       schema.TypeString,
				Optional:   true,
				Computed:   true,
				Deprecated: "This field is computed by the API from the servers block and cannot be set directly. Use servers.origin_host instead.",
			},
			"orig_tls": {
				Type:       schema.TypeString,
				Optional:   true,
				Computed:   true,
				Deprecated: "This field is computed by the API from the servers block and cannot be set directly. Use servers.orig_tls instead.",
			},
			"origin_port": {
				Type:       schema.TypeInt,
				Optional:   true,
				Computed:   true,
				Deprecated: "This field is computed by the API from the servers block and cannot be set directly. Use servers.origin_port instead.",
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
				Type:     schema.TypeSet,
				Optional: true,
				Set:      serversSetHash,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"origin_host": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"orig_tls": {
							Type:       schema.TypeBool,
							Optional:   true,
							Computed:   true,
							Deprecated: "This field is computed by the API and cannot be set directly. The API determines TLS settings based on the origin_protocol value.",
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
				Computed: true,
			},
			"popname": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"popregion": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
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
				Computed: true,
			},
			"app_status": {
				Type:     schema.TypeInt,
				Computed: true,
			},

			"app_deployed": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"cname": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"uuid_url": {
				Type:     schema.TypeString,
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
				Computed: true,
			},
			"cert_body": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"advanced_settings": {
				Type:             schema.TypeMap,
				Optional:         true,
				Computed:         true,
				Elem:             &schema.Schema{Type: schema.TypeString},
				DiffSuppressFunc: suppressServerComputedAdvSettingsKey,
				Description: "Flat map of advanced settings key/value pairs. All values are strings. " +
					"Entries are passed to the API as provided; unsupported keys may be ignored by the API.  " +
					"Complex fields (form_post_attributes, custom_headers, rdp_remote_apps) must be JSON-encoded strings.",
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
	// Validate authentication methods for app type (always run this validation)
	authErr := validateAuthenticationMethodsForAppTypeWithDiff(d)
	if authErr != nil {
		return authErr
	}

	// Validate WSFED nested blocks
	err := client.ValidateWSFEDNestedBlocks(ctx, d, m)

	// Validate SAML nested blocks
	if err == nil {
		err = client.ValidateSAMLNestedBlocks(ctx, d, m)
	}

	// Validate OIDC nested blocks
	if err == nil {
		err = client.ValidateOIDCNestedBlocks(ctx, d, m)
	}

	return err
}

// resourceEaaApplicationCreateTwoPhase implements the two-phase application creation approach
// Phase 1: Create app with minimal required fields
// Phase 2: Configure additional settings (agents, authentication, advanced settings, deployment)
func resourceEaaApplicationCreateTwoPhase(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagApp, logging.TagCreate}
	logging.Info(ctx, "creating application (two-phase)", tags)

	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}
	var warningDiags diag.Diagnostics

	var appUUIDURL string
	var phase2Steps []func() error

	// ========================================
	// PHASE 1: Create minimal application
	// ========================================
	logging.Debug(ctx, "phase 1: creating minimal application", tags)

	minimalRequest := client.MinimalCreateAppRequest{}
	err = minimalRequest.CreateMinimalAppRequestFromSchema(ctx, d, eaaclient)
	if err != nil {
		logging.Warn(ctx, "Phase 1 failed: create minimal app request failed", tags, map[string]any{"error": err.Error()})
		return append(warningDiags, logging.DiagFromErr(err, tags, "Phase 1 failed: create minimal app request failed")...)
	}

	appResp, err := minimalRequest.CreateMinimalApplication(ctx, eaaclient)
	if err != nil {
		logging.Warn(ctx, "Phase 1 failed: create minimal application failed", tags, map[string]any{"error": err.Error()})
		return append(warningDiags, logging.DiagFromErr(err, tags, "Phase 1 failed: create minimal application failed")...)
	}

	appUUIDURL = appResp.UUIDURL
	logging.Debug(ctx, "phase 1 succeeded: application created", tags, map[string]any{"app_id": appUUIDURL})

	// Set the resource ID early so cleanup can work if later steps fail
	d.SetId(appUUIDURL)

	// ========================================
	// PHASE 2: Configure additional settings
	// ========================================
	logging.Debug(ctx, "phase 2: configuring additional settings", tags)

	// Prepare Phase 2 steps for potential rollback
	phase2Steps = []func() error{
		func() error {
			logging.Debug(ctx, "phase 2: configuring agents", tags)
			return client.ConfigureAgents(ctx, appUUIDURL, d, eaaclient)
		},
		func() error {
			logging.Debug(ctx, "phase 2: configuring authentication", tags)
			return client.ConfigureAuthentication(ctx, appUUIDURL, d, eaaclient)
		},
		func() error {
			logging.Debug(ctx, "phase 2: configuring access service", tags)
			return client.ConfigureService(ctx, appUUIDURL, d, eaaclient)
		},
		func() error {
			logging.Debug(ctx, "phase 2: configuring advanced settings", tags)
			return client.ConfigureAdvancedSettings(ctx, appUUIDURL, d, eaaclient)
		},
		func() error {
			logging.Debug(ctx, "phase 2: deploying application", tags)
			return client.DeployExistingApplication(ctx, appUUIDURL, eaaclient)
		},
	}

	// Execute Phase 2 steps with error handling
	for i, step := range phase2Steps {
		if err := step(); err != nil {
			logging.Warn(ctx, fmt.Sprintf("phase 2 step %d failed, attempting cleanup", i+1), tags, map[string]any{"error": err.Error()})

			if !cleanupOrphanedApp(ctx, eaaclient, appUUIDURL) {
				logging.Warn(ctx, "failed to clean up orphaned app", tags)
				return append(append(warningDiags, logging.DiagFromErr(err, tags, "Phase 2 failed")...), logging.DiagWarningf(tags, "Application %s was created but configuration failed. Manual cleanup may be required.", appUUIDURL)...)
			}

			d.SetId("")
			return append(warningDiags, logging.DiagFromErr(err, tags, "Phase 2 failed")...)
		}
		logging.Debug(ctx, fmt.Sprintf("phase 2 step %d completed", i+1), tags)
	}

	logging.Info(ctx, "application created successfully (two-phase)", tags)

	// Return the read result
	return append(warningDiags, resourceEaaApplicationRead(ctx, d, m)...)
}

// resourceEaaApplicationRead function reads an existing EAA application.
// fetches application details using and maps the response to the schema attributes.

func resourceEaaApplicationRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagApp, logging.TagRead}
	logging.Info(ctx, "reading application", tags)

	id := d.Id()
	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}
	var appResp client.ApplicationResponse

	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, id)

	getResp, err := eaaclient.SendAPIRequest(ctx, apiURL, "GET", nil, &appResp, false)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to read application")
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		return logging.DiagFromErr(getAppError(getResp), tags, "application get failed")
	}

	var diags diag.Diagnostics

	// Map basic attributes
	diags = append(diags, mapBasicAttributesFromResponse(ctx, d, &appResp, eaaclient)...)

	// Map servers and tunnel hosts
	diags = append(diags, mapServersAndTunnelHostsFromResponse(d, &appResp)...)

	// Map advanced settings
	diags = append(diags, mapAdvancedSettingsFromResponse(d, &appResp)...)

	// Map agents, authentication, cert, and service
	diags = append(diags, mapAgentsAndAuthFromResponse(ctx, d, &appResp, eaaclient)...)

	// Map SAML settings
	diags = append(diags, mapSAMLSettingsFromResponse(d, &appResp)...)

	// Map WSFED settings
	diags = append(diags, mapWSFEDSettingsFromResponse(d, &appResp)...)

	// Map OIDC settings
	diags = append(diags, mapOIDCSettingsFromResponse(d, &appResp)...)

	return diags
}

// resourceEaaApplicationUpdate function updates an existing EAA application.
// fetches the application, updates it based on the changed attributes, and deploys the application.
// then calls the read function to ensure the updated data is correctly populated in the schema.

func resourceEaaApplicationUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagApp, logging.TagUpdate}
	logging.Info(ctx, "updating application", tags)

	// Set the resource ID
	id := d.Id()
	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}
	var warningDiags diag.Diagnostics

	// Advanced settings validation is now handled at plan time via CustomizeDiff

	var appResp client.Application

	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, id)

	getResp, err := eaaclient.SendAPIRequest(ctx, apiURL, "GET", nil, &appResp, false)
	if err != nil {
		return append(warningDiags, logging.DiagFromErr(err, tags, "failed to read application for update")...)
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		return append(warningDiags, logging.DiagFromErr(getAppError(getResp), tags, "application get failed")...)
	}

	// Store the update request for later use after IDP assignment
	appUpdateReq := client.ApplicationUpdateRequest{}
	appUpdateReq.Application = appResp
	err = appUpdateReq.UpdateAppRequestFromSchema(ctx, d, eaaclient)
	if err != nil {
		return append(warningDiags, logging.DiagFromErr(err, tags, "failed to build update request")...)
	}

	currAgents, err := appResp.GetAppAgents(ctx, eaaclient)
	if err != nil {
		return append(warningDiags, logging.DiagFromErr(err, tags, "failed to get current agents")...)
	}
	if agentsRaw, ok := d.GetOk("agents"); ok {
		agentList, ok := agentsRaw.([]interface{})
		if !ok {
			return append(warningDiags, logging.DiagFromErr(ErrInvalidData, tags, "invalid agent data in schema")...)
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
				return append(warningDiags, logging.DiagFromErr(assignErr, tags, "failed to assign agents")...)
			}
		}
		if len(agentsToUnassign) > 0 {
			var agents client.AssignAgents
			agents.AppID = id
			agents.AgentNames = append(agents.AgentNames, agentsToUnassign...)

			unassignErr := agents.UnAssignAgents(ctx, eaaclient)
			if unassignErr != nil {
				return append(warningDiags, logging.DiagFromErr(unassignErr, tags, "failed to unassign agents")...)
			}
		}
	}
	if d.HasChange("app_authentication") {
		authEnabledValue := "false"

		if aE, ok := d.GetOk("auth_enabled"); ok {
			authEnabled, ok := aE.(string)
			if !ok {
				return append(warningDiags, logging.DiagFromErr(ErrInvalidData, tags, "invalid auth_enabled data")...)
			}
			authEnabledValue = authEnabled
		}

		if authEnabledValue == "true" {
			if appAuth, ok := d.GetOk("app_authentication"); ok {
				appUUIDURL := id
				appIDPMembership, membershipErr := appResp.GetAppIdpMembership(ctx, eaaclient)
				if membershipErr != nil {
					return append(warningDiags, logging.DiagFromErr(membershipErr, tags, "failed to get app IDP membership")...)
				}
				if appIDPMembership != nil {
					appIdp := client.AppIdp{
						App: appUUIDURL,
						IDP: appIDPMembership.UUIDURL,
					}
					err = appIdp.UnAssignIDP(ctx, eaaclient)
					if err != nil {
						logging.Warn(ctx, "IDP unassign error", tags, map[string]any{"error": err.Error()})
						return append(warningDiags, logging.DiagFromErr(err, tags, "failed to unassign IDP")...)
					}
				}
				appAuthList, ok := appAuth.([]interface{})
				if !ok {
					return append(warningDiags, logging.DiagFromErr(ErrInvalidData, tags, "invalid authentication data")...)
				}
				if appAuthList == nil {
					return append(warningDiags, logging.DiagFromErr(ErrInvalidData, tags, "authentication data is nil")...)
				}
				if len(appAuthList) > 0 {
					appAuthenticationMap, mapOK := appAuthList[0].(map[string]interface{})
					if !mapOK {
						logging.Error(ctx, "app_authentication block has unexpected type in UPDATE", tags)
						return append(warningDiags, logging.DiagFromErr(ErrInvalidData, tags, "invalid authentication map data")...)
					}
					if appAuthenticationMap == nil {
						logging.Debug(ctx, "app_authentication block is empty in UPDATE, skipping", tags)
						return warningDiags
					}
					if appIDPName, ok := appAuthenticationMap["app_idp"].(string); ok && appIDPName != "" {
						idpData, getIDPErr := client.GetIdpWithName(ctx, eaaclient, appIDPName)
						if getIDPErr != nil {
							logging.Warn(ctx, "get IDP with name error", tags, map[string]any{"error": getIDPErr.Error()})
							return append(warningDiags, logging.DiagFromErr(getIDPErr, tags, "failed to get IDP with name")...)
						}
						if idpData == nil {
							return append(warningDiags, logging.DiagErrorf(tags, "IDP '%s' not found", appIDPName)...)
						}

						logging.Debug(ctx, "assigning IDP to application in UPDATE", tags, map[string]any{
							"app_uuid_url": appUUIDURL,
							"idp_uuid_url": idpData.UUIDURL,
						})

						appIdp := client.AppIdp{
							App: appUUIDURL,
							IDP: idpData.UUIDURL,
						}
						err = appIdp.AssignIDP(ctx, eaaclient)
						if err != nil {
							logging.Warn(ctx, "IDP assign error in UPDATE", tags, map[string]any{"error": err.Error()})
							return append(warningDiags, logging.DiagFromErr(err, tags, "failed to assign IDP")...)
						}
						logging.Debug(ctx, "IDP assigned successfully in UPDATE", tags, map[string]any{"app_name": appResp.Name, "idp": appIDPName})

						if appDirs, ok := appAuthenticationMap["app_directories"]; ok {
							logging.Debug(ctx, "starting directory assignment in UPDATE...", tags)
							directoryErr := idpData.AssignIdpDirectories(ctx, appDirs, appUUIDURL, eaaclient)
							if directoryErr != nil {
								logging.Warn(ctx, "directory assignment error in UPDATE", tags, map[string]any{"error": directoryErr.Error()})
								return append(warningDiags, logging.DiagFromErr(directoryErr, tags, "failed to assign directories")...)
							}
							logging.Debug(ctx, "directory assignment completed successfully in UPDATE", tags)
						} else {
							logging.Debug(ctx, "no app_directories found in UPDATE, skipping directory assignment", tags)
						}

						logging.Debug(ctx, "IDP assignment complete in UPDATE flow", tags)
					}
				}
			}
		}
	}

	if d.HasChange("service") {
		servicesRaw, hasService := d.GetOk("service")
		var services []interface{}
		if hasService {
			var ok bool
			services, ok = servicesRaw.([]interface{})
			if !ok {
				return append(warningDiags, logging.DiagFromErr(ErrInvalidData, tags, "invalid service data")...)
			}
		}

		if len(services) > 0 {
			appUUIDURL := appResp.UUIDURL
			appSrv, serviceErr := client.GetACLService(ctx, eaaclient, appUUIDURL)
			if serviceErr != nil {
				return append(warningDiags, logging.DiagFromErr(serviceErr, tags, "failed to get ACL service")...)
			}

			aclSrv, extractErr := client.ExtractACLService(ctx, d, eaaclient)
			if extractErr != nil {
				return append(warningDiags, logging.DiagFromErr(extractErr, tags, "failed to extract ACL service")...)
			}

			if appSrv.Status != aclSrv.Status {
				appSrv.Status = aclSrv.Status
				if serviceErr := appSrv.EnableService(ctx, eaaclient); serviceErr != nil {
					return append(warningDiags, logging.DiagFromErr(serviceErr, tags, "failed to enable service")...)
				}
			}
			if d.HasChange("service.0.access_rule") {
				// Fetch existing rules
				existingACLResponse, rulesErr := client.GetAccessControlRules(ctx, eaaclient, appSrv.UUIDURL)
				if rulesErr != nil {
					return append(warningDiags, logging.DiagFromErr(rulesErr, tags, "failed to get access control rules")...)
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
							return append(warningDiags, logging.DiagFromErr(deleteErr, tags, "failed to delete access rule")...)
						}
					}
				}

				// Handle creations and modifications
				for name, newRule := range newRulesMap {
					if existingRule, exists := existingRulesMap[name]; exists {
						if !existingRule.IsEqual(newRule) {
							newRule.UUID_URL = existingRule.UUID_URL
							if modifyErr := newRule.ModifyAccessRule(ctx, eaaclient, appSrv.UUIDURL); modifyErr != nil {
								return append(warningDiags, logging.DiagFromErr(modifyErr, tags, "failed to modify access rule")...)
							}
						}
					} else {
						// Create new rule
						if createErr := newRule.CreateAccessRule(ctx, eaaclient, appSrv.UUIDURL); createErr != nil {
							return append(warningDiags, logging.DiagFromErr(createErr, tags, "failed to create access rule")...)
						}
					}
				}
			}
		}
	}

	// Now perform the PUT call to update advanced settings AFTER IDP assignment is complete
	logging.Debug(ctx, "performing PUT call after IDP assignment in UPDATE flow", tags)
	err = appUpdateReq.UpdateApplication(ctx, eaaclient)
	if err != nil {
		logging.Warn(ctx, "PUT call failed after IDP assignment in UPDATE", tags, map[string]any{"error": err.Error()})
		return append(warningDiags, logging.DiagFromErr(err, tags, "failed to update application")...)
	}
	logging.Debug(ctx, "PUT call completed successfully in UPDATE flow", tags)

	// Add delay before deploy in UPDATE flow to ensure all operations are complete
	logging.Debug(ctx, "waiting before deploy in UPDATE flow...", tags)

	err = appUpdateReq.DeployApplication(ctx, eaaclient)
	if err != nil {
		return append(warningDiags, logging.DiagFromErr(err, tags, "failed to deploy application")...)
	}

	logging.Info(ctx, "application updated successfully", tags)
	return append(warningDiags, resourceEaaApplicationRead(ctx, d, m)...)
}

// resourceEaaApplicationDelete function deletes an existing EAA application.
// sends a delete request to the EAA client to remove the application.
func resourceEaaApplicationDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagApp, logging.TagDelete}
	logging.Info(ctx, "deleting application", tags)

	// Read the resource ID from d
	id := d.Id()
	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}
	var appResp client.ApplicationDataModel

	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, id)
	getResp, err := eaaclient.SendAPIRequest(ctx, apiURL, "GET", nil, &appResp, false)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to read application for delete")
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		return logging.DiagFromErr(getAppError(getResp), tags, "application get failed")
	}
	err = appResp.DeleteApplication(ctx, eaaclient)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to delete application")
	}

	// Set the resource ID to mark it as deleted
	d.SetId("")

	logging.Info(ctx, "application deleted successfully", tags)
	return nil
}
