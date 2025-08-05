package eaaprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

var (
	ErrGetApp      = errors.New("app get failed")
	ErrInvalidData = errors.New("invalid data in schema")
)

func resourceEaaApplication() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceEaaApplicationCreate,
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
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MinItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"sp": {
							Type:     schema.TypeList,
							Required: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"entity_id": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "",
									},
									"acs_url": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "",
									},
									"slo_url": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "",
									},
									"req_bind": {
										Type:         schema.TypeString,
										Optional:     true,
										Default:      "redirect",
										ValidateFunc: validation.StringInSlice([]string{"redirect", "post"}, false),
									},
									"metadata": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"default_relay_state": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"force_auth": {
										Type:     schema.TypeBool,
										Optional: true,
										Default:  false,
									},
									"req_verify": {
										Type:     schema.TypeBool,
										Optional: true,
										Default:  false,
									},
									"sign_cert": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "",
									},
									"resp_encr": {
										Type:     schema.TypeBool,
										Optional: true,
										Default:  false,
									},
									"encr_cert": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "",
									},
									"encr_algo": {
										Type:         schema.TypeString,
										Optional:     true,
										Default:      "aes256-cbc",
										ValidateFunc: validation.StringInSlice([]string{"aes256-cbc", "aes128-cbc"}, false),
									},
									"slo_req_verify": {
										Type:     schema.TypeBool,
										Optional: true,
										Default:  true,
									},
									"dst_url": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "",
									},
									"slo_bind": {
										Type:         schema.TypeString,
										Optional:     true,
										Default:      "post",
										ValidateFunc: validation.StringInSlice([]string{"post", "redirect"}, false),
									},
								},
							},
						},
						"idp": {
							Type:     schema.TypeList,
							Required: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"entity_id": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"metadata": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"sign_cert": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"sign_key": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"self_signed": {
										Type:     schema.TypeBool,
										Optional: true,
										Default:  true,
									},
									"sign_algo": {
										Type:         schema.TypeString,
										Optional:     true,
										Default:      "SHA256",
										ValidateFunc: validation.StringInSlice([]string{"SHA256", "SHA1"}, false),
									},
									"resp_bind": {
										Type:         schema.TypeString,
										Optional:     true,
										Default:      "post",
										ValidateFunc: validation.StringInSlice([]string{"post"}, false),
									},
									"slo_url": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"ecp_enable": {
										Type:     schema.TypeBool,
										Optional: true,
										Default:  false,
									},
									"ecp_resp_signature": {
										Type:     schema.TypeBool,
										Optional: true,
										Default:  false,
									},
								},
							},
						},
						"subject": {
							Type:     schema.TypeList,
							Required: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"fmt": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: validation.StringInSlice([]string{"email", "persistent", "unspecified", "transient"}, false),
									},
									"src": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: validateSubjectFmtSrc,
									},
									"val": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"rule": {
										Type:     schema.TypeString,
										Optional: true,
									},
								},
							},
						},
						"attrmap": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:     schema.TypeString,
										Required: true,
									},
									"fname": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"fmt": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: validation.StringInSlice([]string{
											"email",
											"phone",
											"country",
											"firstName",
											"lastName",
											"groups",
											"netbios",
											"persistentId",
											"samAccountName",
											"userPrincipleName",
										}, false),
									},
									"val": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"src": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: validateAttrmapFmtSrc,
									},
									"rule": {
										Type:     schema.TypeString,
										Optional: true,
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
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MinItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"sp": {
							Type:     schema.TypeList,
							Required: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"entity_id": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "",
									},
									"slo_url": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "",
									},
									"dst_url": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "",
									},
									"resp_bind": {
										Type:         schema.TypeString,
										Optional:     true,
										Default:      "post",
										ValidateFunc: validation.StringInSlice([]string{"post"}, false),
									},
									"token_life": {
										Type:     schema.TypeInt,
										Optional: true,
										Default:  3600,
									},
									"encr_algo": {
										Type:         schema.TypeString,
										Optional:     true,
										Default:      "aes256-cbc",
										ValidateFunc: validation.StringInSlice([]string{"aes256-cbc", "aes128-cbc"}, false),
									},
								},
							},
						},
						"idp": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"entity_id": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "",
									},
									"sign_algo": {
										Type:         schema.TypeString,
										Optional:     true,
										Default:      "SHA256",
										ValidateFunc: validation.StringInSlice([]string{"SHA256", "SHA1"}, false),
									},
									"sign_cert": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "",
									},
									"sign_key": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "",
									},
									"self_signed": {
										Type:     schema.TypeBool,
										Optional: true,
										Default:  true,
									},
								},
							},
						},
						"subject": {
							Type:     schema.TypeList,
							Required: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"fmt": {
										Type:     schema.TypeString,
										Required: true,
									},
									"custom_fmt": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"src": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"val": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"rule": {
										Type:     schema.TypeString,
										Optional: true,
									},
								},
							},
						},
						"attrmap": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"fmt": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: validation.StringInSlice([]string{"email", "phone", "country", "firstName", "lastName", "groups", "netbios", "persistentId", "samAccountName", "userPrincipleName"}, false),
									},
									"custom_fmt": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"val": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"src": {
										Type:         schema.TypeString,
										Optional:     true,
										ValidateFunc: validateWSFEDAttrmapFmtSrc,
									},
									"rule": {
										Type:     schema.TypeString,
										Optional: true,
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
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MinItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"authorization_endpoint": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"certs_uri": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"check_session_iframe": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"discovery_url": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"end_session_endpoint": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"jwks_uri": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"openid_metadata": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"token_endpoint": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"userinfo_endpoint": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
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
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"is_ssl_verification_enabled": {
							Type:         schema.TypeString,
							Optional:     true,
							Default:      "false",
							ValidateFunc: validation.StringInSlice([]string{"true", "false"}, false),
						},
						"edge_authentication_enabled": {
							Type:         schema.TypeString,
							Optional:     true,
							Default:      "false",
							ValidateFunc: validation.StringInSlice([]string{"true", "false"}, false),
						},
						"ignore_cname_resolution": {
							Type:         schema.TypeString,
							Optional:     true,
							Default:      "false",
							ValidateFunc: validation.StringInSlice([]string{"true", "false"}, false),
						},
						"g2o_enabled": {
							Type:         schema.TypeString,
							Optional:     true,
							Default:      "false",
							ValidateFunc: validation.StringInSlice([]string{"true", "false"}, false),
						},
						"g2o_nonce": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"g2o_key": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"x_wapp_read_timeout": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "900",
						},
						"internal_hostname": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "",
						},
						"internal_host_port": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "0",
						},
						"ip_access_allow": {
							Type:         schema.TypeString,
							Optional:     true,
							Default:      "false",
							ValidateFunc: validation.StringInSlice([]string{"true", "false"}, false),
						},
						"wildcard_internal_hostname": {
							Type:         schema.TypeString,
							Optional:     true,
							Default:      "false",
							ValidateFunc: validation.StringInSlice([]string{"true", "false"}, false),
						},
						"edge_cookie_key": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"sla_object_url": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"websocket_enabled": {
							Type:         schema.TypeString,
							Optional:     true,
							Default:      "false",
							ValidateFunc: validation.StringInSlice([]string{"true", "false"}, false),
						},
						"sticky_agent": {
							Type:         schema.TypeString,
							Optional:     true,
							Default:      "false",
							ValidateFunc: validation.StringInSlice([]string{"true", "false"}, false),
						},
						"sentry_redirect_401": {
							Type:         schema.TypeString,
							Optional:     true,
							Default:      "off",
							ValidateFunc: validation.StringInSlice([]string{"on", "off"}, false),
						},
						"app_cookie_domain": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"logout_url": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"allow_cors": {
							Type:         schema.TypeString,
							Optional:     true,
							Default:      "false",
							ValidateFunc: validation.StringInSlice([]string{"true", "false"}, false),
						},
						"cors_origin_list": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "unbounded",
						},
						"cors_method_list": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "unbounded",
						},
						"cors_header_list": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "unbounded",
						},
						"cors_max_age": {
							Type:     schema.TypeInt,
							Optional: true,
							Default:  86400,
						},
						"cors_support_credential": {
							Type:         schema.TypeString,
							Optional:     true,
							Default:      "on",
							ValidateFunc: validation.StringInSlice([]string{"on", "off"}, false),
						},
						"app_auth": {
							Type:         schema.TypeString,
							Optional:     true,
							Default:      "none",
							ValidateFunc: validation.StringInSlice([]string{"none", "kerberos", "basic", "NTLMv1", "NTLMv2", "SAML2.0", "WS-Federation", "oidc", "OpenID Connect 1.0"}, false),
						},
						"app_auth_domain": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "",
						},
						"app_client_cert_auth": {
							Type:         schema.TypeString,
							Optional:     true,
							Default:      "false",
							ValidateFunc: validation.StringInSlice([]string{"true", "false"}, false),
						},
						"forward_ticket_granting_ticket": {
							Type:         schema.TypeString,
							Optional:     true,
							Default:      "false",
							ValidateFunc: validation.StringInSlice([]string{"true", "false"}, false),
						},
						"keytab": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "",
						},
						"service_principal_name": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "",
						},
						"custom_headers": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"attribute_type": {
										Type:         schema.TypeString,
										Optional:     true,
										ValidateFunc: validation.StringInSlice([]string{"user", "group", "clientip", "fixed", "custom"}, false),
									},
									"attribute": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"header": {
										Type:     schema.TypeString,
										Optional: true,
									},
								},
							},
						},
						"wapp_auth": {
    Type:         schema.TypeString,
    Optional:     true,
    Computed:     true,
    ValidateFunc: validation.StringInSlice([]string{"form", "basic", "basic_cookie", "jwt"}, false),
},
"jwt_issuers": {
    Type:     schema.TypeString,
    Optional: true,
    Computed: true,
},
"jwt_audience": {
    Type:     schema.TypeString,
    Optional: true,
    Computed: true,
},
"jwt_grace_period": {
    Type:     schema.TypeString,
    Optional: true,
    Computed: true,
},
"jwt_return_option": {
    Type:     schema.TypeString,
    Optional: true,
    Computed: true,
},
"jwt_username": {
    Type:     schema.TypeString,
    Optional: true,
    Computed: true,
},
"jwt_return_url": {
    Type:     schema.TypeString,
    Optional: true,
    Computed: true,
},
					},
				},
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
	}
}

// validateAttrmapFmtSrc validates that src values are valid user attributes
func validateAttrmapFmtSrc(i interface{}, k string) (warnings []string, errors []error) {
	v, ok := i.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected type of %s to be string", k))
		return warnings, errors
	}

	// Define the allowed src values
	allowedSrcs := []string{
		"user.phoneNumber",
		"user.countryCode", 
		"user.firstName",
		"user.email",
		"user.lastName",
		"user.groups",
		"user.netbios",
		"user.persistentId",
		"user.samAccountName",
		"user.userPrincipleName",
	}

	// Check if the value is in the allowed src values
	for _, allowedSrc := range allowedSrcs {
		if v == allowedSrc {
			return warnings, errors
		}
	}

	errors = append(errors, fmt.Errorf("invalid src value: %s. Must be one of: user.email, user.phoneNumber, user.countryCode, user.firstName, user.lastName, user.groups, user.netbios, user.persistentId, user.samAccountName, user.userPrincipleName", v))
	return warnings, errors
}

// validateAttrmapBlock validates that fmt and src values are properly matched within each attrmap block
func validateAttrmapBlock(i interface{}, k string) (warnings []string, errors []error) {
	attrmapList, ok := i.([]interface{})
	if !ok {
		errors = append(errors, fmt.Errorf("expected type of %s to be list", k))
		return warnings, errors
	}

	// Define the mapping of fmt values to allowed src values
	fmtToSrcMap := map[string]string{
		"email":         "user.email",
		"phone":         "user.phoneNumber",
		"country":       "user.countryCode",
		"firstName":     "user.firstName",
		"lastName":      "user.lastName",
		"groups":        "user.groups",
		"netbios":       "user.netbios",
		"persistentId":  "user.persistentId",
		"samAccountName": "user.samAccountName",
		"userPrincipleName": "user.userPrincipleName",
	}

	for _, attrmapItem := range attrmapList {
		if attrmapMap, ok := attrmapItem.(map[string]interface{}); ok {
			if fmtVal, fmtOk := attrmapMap["fmt"].(string); fmtOk {
				if srcVal, srcOk := attrmapMap["src"].(string); srcOk {
					expectedSrc, exists := fmtToSrcMap[fmtVal]
					if !exists {
						errors = append(errors, fmt.Errorf("invalid fmt value: %s", fmtVal))
						continue
					}
					if srcVal != expectedSrc {
						errors = append(errors, fmt.Errorf("fmt value '%s' must be paired with src value '%s', but got '%s'", fmtVal, expectedSrc, srcVal))
					}
				}
			}
		}
	}

	return warnings, errors
}

// validateSubjectFmtSrc validates that src values are valid user attributes for subject
func validateSubjectFmtSrc(i interface{}, k string) (warnings []string, errors []error) {
	v, ok := i.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected type of %s to be string", k))
		return warnings, errors
	}

	// Define the allowed src values for subject
	allowedSrcs := []string{
		"user.email",
		"user.persistentId",
		"user.samAccountName",
		"user.userPrincipleName",
	}

	// Check if the value is in the allowed src values
	for _, allowedSrc := range allowedSrcs {
		if v == allowedSrc {
			return warnings, errors
		}
	}

	errors = append(errors, fmt.Errorf("invalid src value for subject: %s. Must be one of: user.email, user.persistentId, user.samAccountName, user.userPrincipleName", v))
	return warnings, errors
}

// validateSubjectBlock validates that fmt and src values are properly matched within the subject block
func validateSubjectBlock(i interface{}, k string) (warnings []string, errors []error) {
	subjectList, ok := i.([]interface{})
	if !ok {
		errors = append(errors, fmt.Errorf("expected type of %s to be list", k))
		return warnings, errors
	}

	// Define the mapping of fmt values to allowed src values for subject
	fmtToSrcMap := map[string]string{
		"email":      "user.email",
		"persistent": "user.persistentId",
		"transient":  "user.samAccountName",
		"unspecified": "user.userPrincipleName",
	}

	for _, subjectItem := range subjectList {
		if subjectMap, ok := subjectItem.(map[string]interface{}); ok {
			if fmtVal, fmtOk := subjectMap["fmt"].(string); fmtOk {
				if srcVal, srcOk := subjectMap["src"].(string); srcOk {
					expectedSrc, exists := fmtToSrcMap[fmtVal]
					if !exists {
						errors = append(errors, fmt.Errorf("invalid fmt value for subject: %s", fmtVal))
						continue
					}
					if srcVal != expectedSrc {
						errors = append(errors, fmt.Errorf("subject fmt value '%s' must be paired with src value '%s', but got '%s'", fmtVal, expectedSrc, srcVal))
					}
				}
			}
		}
	}

	return warnings, errors
}

// validateWSFEDAttrmapFmtSrc validates that src values are valid user attributes for WS-Federation attrmap
func validateWSFEDAttrmapFmtSrc(i interface{}, k string) (warnings []string, errors []error) {
	v, ok := i.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected type of %s to be string", k))
		return warnings, errors
	}

	// Define the allowed src values for WS-Federation attrmap (same as SAML)
	allowedSrcs := []string{
		"user.phoneNumber",
		"user.countryCode",
		"user.firstName",
		"user.email",
		"user.lastName",
		"user.groups",
		"user.netbios",
		"user.persistentId",
		"user.samAccountName",
		"user.userPrincipleName",
	}

	// Check if the value is in the allowed src values
	for _, allowedSrc := range allowedSrcs {
		if v == allowedSrc {
			return warnings, errors
		}
	}

	errors = append(errors, fmt.Errorf("invalid src value for WS-Federation attrmap: %s. Must be one of: user.phoneNumber, user.countryCode, user.firstName, user.email, user.lastName, user.groups, user.netbios, user.persistentId, user.samAccountName, user.userPrincipleName", v))
	return warnings, errors
}

// validateWSFEDAttrmapBlock validates that fmt and src values are properly matched within the WS-Federation attrmap block
func validateWSFEDAttrmapBlock(i interface{}, k string) (warnings []string, errors []error) {
	attrmapList, ok := i.([]interface{})
	if !ok {
		errors = append(errors, fmt.Errorf("expected type of %s to be list", k))
		return warnings, errors
	}

	// Define the mapping of fmt values to allowed src values (same as SAML)
	fmtToSrcMap := map[string]string{
		"email":         "user.email",
		"phone":         "user.phoneNumber",
		"country":       "user.countryCode",
		"firstName":     "user.firstName",
		"lastName":      "user.lastName",
		"groups":        "user.groups",
		"netbios":       "user.netbios",
		"persistentId":  "user.persistentId",
		"samAccountName": "user.samAccountName",
		"userPrincipleName": "user.userPrincipleName",
	}

	for _, attrmapItem := range attrmapList {
		if attrmapMap, ok := attrmapItem.(map[string]interface{}); ok {
			if fmtVal, fmtOk := attrmapMap["fmt"].(string); fmtOk {
				if srcVal, srcOk := attrmapMap["src"].(string); srcOk {
					expectedSrc, exists := fmtToSrcMap[fmtVal]
					if !exists {
						errors = append(errors, fmt.Errorf("invalid fmt value for WS-Federation attrmap: %s", fmtVal))
						continue
					}
					if srcVal != expectedSrc {
						errors = append(errors, fmt.Errorf("WS-Federation attrmap fmt value '%s' must be paired with src value '%s', but got '%s'", fmtVal, expectedSrc, srcVal))
					}
				}
			}
		}
	}

	return warnings, errors
}

// validateOIDCClaim validates OIDC claim fields based on the schema requirements
func validateOIDCClaim(i interface{}, k string) (warnings []string, errors []error) {
	claimList, ok := i.([]interface{})
	if !ok {
		errors = append(errors, fmt.Errorf("expected type of %s to be list", k))
		return warnings, errors
	}

	for _, claimItem := range claimList {
		if claimMap, ok := claimItem.(map[string]interface{}); ok {
			// Check required fields: name and scope
			if name, nameOk := claimMap["name"].(string); !nameOk || name == "" {
				errors = append(errors, fmt.Errorf("claim name is required and cannot be blank"))
			}
			if scope, scopeOk := claimMap["scope"].(string); !scopeOk || scope == "" {
				errors = append(errors, fmt.Errorf("claim scope is required and cannot be blank"))
			}

			// Check that at least one of src, rule, or val is provided
			src, srcOk := claimMap["src"].(string)
			rule, ruleOk := claimMap["rule"].(string)
			val, valOk := claimMap["val"].(string)

			if (!srcOk || src == "") && (!ruleOk || rule == "") && (!valOk || val == "") {
				errors = append(errors, fmt.Errorf("claim must have at least one of: src, rule, or val"))
			}
		}
	}

	return warnings, errors
}

// validateOIDCClaimFmtSrc validates that src values are valid for OIDC claims
func validateOIDCClaimFmtSrc(i interface{}, k string) (warnings []string, errors []error) {
	v, ok := i.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected type of %s to be string", k))
		return warnings, errors
	}

	// Define the allowed src values for OIDC claims
	allowedSrcs := []string{
		"user.email",
		"user.name", 
		"user.id",
		"user.attribute",
		"user.firstName",
		"user.lastName",
		"user.groups",
		"user.phoneNumber",
		"user.countryCode",
		"user.netbios",
		"user.persistentId",
		"user.samAccountName",
		"user.userPrincipleName",
	}

	// Check if the value is in the allowed src values
	for _, allowedSrc := range allowedSrcs {
		if v == allowedSrc {
			return warnings, errors
		}
	}

	errors = append(errors, fmt.Errorf("invalid src value for OIDC claim: %s. Must be one of: user.email, user.name, user.id, user.attribute, user.firstName, user.lastName, user.groups, user.phoneNumber, user.countryCode, user.netbios, user.persistentId, user.samAccountName, user.userPrincipleName", v))
	return warnings, errors
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
		logger.Info("create Application: assigning agents succeeded.")
	}

	appUpdateReq := client.ApplicationUpdateRequest{}
	appUpdateReq.Application = app
	err = appUpdateReq.UpdateAppRequestFromSchema(ctx, d, eaaclient)
	if err != nil {
		return diag.FromErr(err)
	}

	err = appUpdateReq.UpdateApplication(ctx, eaaclient)
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
					logger.Info("app.Name: ", app.Name, "app_idp_name: ", app_idp_name, "idpData.UUIDURL: ", idpData.UUIDURL)

					appIdp := client.AppIdp{
						App: app_uuid_url,
						IDP: idpData.UUIDURL,
					}
					err = appIdp.AssignIDP(eaaclient)
					if err != nil {
						logger.Error("idp assign error err ", err)
						return diag.FromErr(err)
					}
					logger.Info("idp assigned successfully, app.Name ", app.Name, "idp ", app_idp_name)

					// check if app_directories are present
					if appDirs, ok := appAuthenticationMap["app_directories"]; ok {
						err := idpData.AssignIdpDirectories(ctx, appDirs, app_uuid_url, eaaclient)
						if err != nil {
							return diag.FromErr(err)
						}
					}
				}
			}
		}
	}
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

	err = app.DeployApplication(eaaclient)

	if err != nil {
		return diag.FromErr(err)
	}

	// Set the resource ID
	d.SetId(app_uuid_url)
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
		desc, _ := client.FormatErrorResponse(getResp)
		getAppErrMsg := fmt.Errorf("%w: %s", ErrGetApp, desc)
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
	attrs["wsfed"] = appResp.WSFED

	if appResp.CName != nil {
		attrs["cname"] = *appResp.CName
	}

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

	advSettings := make([]map[string]interface{}, 1)

	advSettings[0] = map[string]interface{}{
		"g2o_enabled":                 appResp.AdvancedSettings.G2OEnabled,
		"g2o_nonce":                   appResp.AdvancedSettings.G2ONonce,
		"g2o_key":                     appResp.AdvancedSettings.G2OKey,
		"is_ssl_verification_enabled": appResp.AdvancedSettings.IsSSLVerificationEnabled,
		"ignore_cname_resolution":     appResp.AdvancedSettings.IgnoreCnameResolution,
		"edge_authentication_enabled": appResp.AdvancedSettings.EdgeAuthenticationEnabled,
		"edge_cookie_key":             appResp.AdvancedSettings.EdgeCookieKey,
		"sla_object_url":              appResp.AdvancedSettings.SLAObjectURL,

		"x_wapp_read_timeout":        appResp.AdvancedSettings.XWappReadTimeout,
		"internal_hostname":          appResp.AdvancedSettings.InternalHostname,
		"internal_host_port":         appResp.AdvancedSettings.InternalHostPort,
		"wildcard_internal_hostname": appResp.AdvancedSettings.WildcardInternalHostname,
		"ip_access_allow":            appResp.AdvancedSettings.IPAccessAllow,

		"allow_cors":              appResp.AdvancedSettings.AllowCORS,
		"cors_origin_list":        appResp.AdvancedSettings.CORSOriginList,
		"cors_method_list":        appResp.AdvancedSettings.CORSMethodList,
		"cors_header_list":        appResp.AdvancedSettings.CORSHeaderList,
		"cors_support_credential": appResp.AdvancedSettings.CORSSupportCredential,

		"websocket_enabled":   appResp.AdvancedSettings.WebSocketEnabled,
		"sticky_agent":        appResp.AdvancedSettings.StickyAgent,
		"app_cookie_domain":   appResp.AdvancedSettings.AppCookieDomain,
		"logout_url":          appResp.AdvancedSettings.LogoutURL,
		"sentry_redirect_401": appResp.AdvancedSettings.SentryRedirect401,
		"app_auth":            appResp.AdvancedSettings.AppAuth,
		"app_auth_domain":     appResp.AdvancedSettings.AppAuthDomain,
		"app_client_cert_auth": appResp.AdvancedSettings.AppClientCertAuth,
		"forward_ticket_granting_ticket": appResp.AdvancedSettings.ForwardTicketGrantingTicket,
		"keytab":              appResp.AdvancedSettings.Keytab,
		"service_principal_name": appResp.AdvancedSettings.ServicePrincipleName,
		"wapp_auth":             appResp.AdvancedSettings.WappAuth,
		"jwt_issuers":           appResp.AdvancedSettings.JWTIssuers,
		"jwt_audience":          appResp.AdvancedSettings.JWTAudience,
		"jwt_grace_period":      appResp.AdvancedSettings.JWTGracePeriod,
		"jwt_return_option":     appResp.AdvancedSettings.JWTReturnOption,
		"jwt_username":          appResp.AdvancedSettings.JWTUsername,
		"jwt_return_url":        appResp.AdvancedSettings.JWTReturnURL,
	}
	var corsAge int
	corsAge, err = strconv.Atoi(appResp.AdvancedSettings.CORSMaxAge)
	if err != nil {
		advSettings[0]["cors_max_age"] = corsAge
	}
	custom_headers := make([]map[string]interface{}, len(appResp.AdvancedSettings.CustomHeaders))
	for i, ch := range appResp.AdvancedSettings.CustomHeaders {
		custom_headers[i] = map[string]interface{}{
			"attribute_type": ch.AttributeType,
			"header":         ch.Header,
			"attribute":      ch.Attribute,
		}
	}

	err = d.Set("advanced_settings", advSettings)
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

	// Set SAML settings in state
	// Always set saml_settings to ensure it appears in state (empty array if no settings)
	var samlSettings []map[string]interface{}
	

	if len(appResp.SAMLSettings) > 0 {
		samlSettings = make([]map[string]interface{}, len(appResp.SAMLSettings))
		for i, samlConfig := range appResp.SAMLSettings {
			samlSettings[i] = map[string]interface{}{
				"sp": []map[string]interface{}{
					{
						"entity_id":          samlConfig.SP.EntityID,
						"acs_url":            samlConfig.SP.ACSURL,
						"slo_url":            samlConfig.SP.SLOURL,
						"req_bind":           samlConfig.SP.ReqBind,
						"metadata":           samlConfig.SP.Metadata,
						"default_relay_state": samlConfig.SP.DefaultRelayState,
						"force_auth":         samlConfig.SP.ForceAuth,
						"req_verify":         samlConfig.SP.ReqVerify,
						"sign_cert":          samlConfig.SP.SignCert,
						"resp_encr":          samlConfig.SP.RespEncr,
						"encr_cert":          samlConfig.SP.EncrCert,
						"encr_algo":          samlConfig.SP.EncrAlgo,
						"slo_req_verify":     samlConfig.SP.SLOReqVerify,
						"dst_url":            samlConfig.SP.DSTURL,
						"slo_bind":           samlConfig.SP.SLOBind,
					},
				},
				"idp": []map[string]interface{}{
					{
						"entity_id":         samlConfig.IDP.EntityID,
						"metadata":          samlConfig.IDP.Metadata,
						"sign_cert":         samlConfig.IDP.SignCert,
						"sign_key":          samlConfig.IDP.SignKey,
						"self_signed":       samlConfig.IDP.SelfSigned,
						"sign_algo":         samlConfig.IDP.SignAlgo,
						"resp_bind":         samlConfig.IDP.RespBind,
						"slo_url":           samlConfig.IDP.SLOURL,
						"ecp_enable":        samlConfig.IDP.ECPIsEnabled,
						"ecp_resp_signature": samlConfig.IDP.ECPRespSignature,
					},
				},
				"subject": []map[string]interface{}{
					{
						"fmt":  samlConfig.Subject.Fmt,
						"src":  samlConfig.Subject.Src,
						"val":  samlConfig.Subject.Val,
						"rule": samlConfig.Subject.Rule,
					},
				},
				"attrmap": func() []map[string]interface{} {
					attrMaps := make([]map[string]interface{}, len(samlConfig.Attrmap))
					for j, attrMap := range samlConfig.Attrmap {
						attrMaps[j] = map[string]interface{}{
							"name":  attrMap.Name,
							"fname": attrMap.Fname,
							"fmt":   attrMap.Fmt,
							"val":   attrMap.Val,
							"src":   attrMap.Src,
							"rule":  attrMap.Rule,
						}
					}
					return attrMaps
				}(),
			}
		}
	}
	// Always set saml_settings (empty array if no settings)
	err = d.Set("saml_settings", samlSettings)
	if err != nil {
		return diag.FromErr(err)
	}

	// Set WS-Federation settings in state
	if len(appResp.WSFEDSettings) > 0 {
		wsfedSettings := make([]map[string]interface{}, len(appResp.WSFEDSettings))
		for i, wsfedConfig := range appResp.WSFEDSettings {
			wsfedSettings[i] = map[string]interface{}{
				"sp": []map[string]interface{}{
					{
						"entity_id":  wsfedConfig.SP.EntityID,
						"slo_url":    wsfedConfig.SP.SLOURL,
						"dst_url":    wsfedConfig.SP.DSTURL,
						"resp_bind":  wsfedConfig.SP.RespBind,
						"token_life": wsfedConfig.SP.TokenLife,
						"encr_algo":  wsfedConfig.SP.EncrAlgo,
					},
				},
				"idp": []map[string]interface{}{
					{
						"entity_id":  wsfedConfig.IDP.EntityID,
						"sign_algo":  wsfedConfig.IDP.SignAlgo,
						"sign_cert":  wsfedConfig.IDP.SignCert,
						"sign_key":   wsfedConfig.IDP.SignKey,
						"self_signed": wsfedConfig.IDP.SelfSigned,
					},
				},
				"subject": []map[string]interface{}{
					{
						"fmt":        wsfedConfig.Subject.Fmt,
						"custom_fmt": wsfedConfig.Subject.CustomFmt,
						"src":        wsfedConfig.Subject.Src,
						"val":        wsfedConfig.Subject.Val,
						"rule":       wsfedConfig.Subject.Rule,
					},
				},
				"attrmap": func() []map[string]interface{} {
					attrMaps := make([]map[string]interface{}, len(wsfedConfig.Attrmap))
					for j, attrMap := range wsfedConfig.Attrmap {
						attrMaps[j] = map[string]interface{}{
							"name":       attrMap.Name,
							"fmt":        attrMap.Fmt,
							"custom_fmt": attrMap.CustomFmt,
							"val":        attrMap.Val,
							"src":        attrMap.Src,
							"rule":       attrMap.Rule,
						}
					}
					return attrMaps
				}(),
			}
		}
		err = d.Set("wsfed_settings", wsfedSettings)
		if err != nil {
			return diag.FromErr(err)
		}
	}

	// Set OIDC settings in state
	if appResp.OIDCSettings != nil {
		oidcSetting := map[string]interface{}{
			"authorization_endpoint": appResp.OIDCSettings.AuthorizationEndpoint,
			"certs_uri":              appResp.OIDCSettings.CertsURI,
			"check_session_iframe":   appResp.OIDCSettings.CheckSessionIframe,
			"discovery_url":          appResp.OIDCSettings.DiscoveryURL,
			"end_session_endpoint":   appResp.OIDCSettings.EndSessionEndpoint,
			"jwks_uri":               appResp.OIDCSettings.JWKSURI,
			"openid_metadata":        appResp.OIDCSettings.OpenIDMetadata,
			"token_endpoint":         appResp.OIDCSettings.TokenEndpoint,
			"userinfo_endpoint":      appResp.OIDCSettings.UserinfoEndpoint,
		}
		err = d.Set("oidc_settings", []map[string]interface{}{oidcSetting})
		if err != nil {
			return diag.FromErr(err)
		}
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
	var appResp client.Application

	apiURL := fmt.Sprintf("%s://%s/%s/%s", client.URL_SCHEME, eaaclient.Host, client.APPS_URL, id)

	getResp, err := eaaclient.SendAPIRequest(apiURL, "GET", nil, &appResp, false)
	if err != nil {
		return diag.FromErr(err)
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc, _ := client.FormatErrorResponse(getResp)
		getAppErrMsg := fmt.Errorf("%w: %s", ErrGetApp, desc)
		return diag.FromErr(getAppErrMsg)
	}

	appUpdateReq := client.ApplicationUpdateRequest{}
	appUpdateReq.Application = appResp
	err = appUpdateReq.UpdateAppRequestFromSchema(ctx, d, eaaclient)
	if err != nil {
		return diag.FromErr(err)
	}

	err = appUpdateReq.UpdateApplication(ctx, eaaclient)
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

						appIdp := client.AppIdp{
							App: app_uuid_url,
							IDP: idpData.UUIDURL,
						}
						err = appIdp.AssignIDP(eaaclient)
						if err != nil {
							eaaclient.Logger.Error("idp assign error err ", err)
							return diag.FromErr(err)
						}

						// check if app_directories are present
						if appDirs, ok := appAuthenticationMap["app_directories"]; ok {
							err := idpData.AssignIdpDirectories(ctx, appDirs, app_uuid_url, eaaclient)
							if err != nil {
								return diag.FromErr(err)
							}
						}
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
		desc, _ := client.FormatErrorResponse(getResp)
		getAppErrMsg := fmt.Errorf("%w: %s", ErrGetApp, desc)
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
