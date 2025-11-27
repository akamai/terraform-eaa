package client

import (
	"reflect"
	"testing"

	"github.com/hashicorp/go-hclog"
)

func TestValidateConditionalRules(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := map[string]struct {
		settingName  string
		value         interface{}
		conditional   map[string]interface{}
		settings      map[string]interface{}
		appType       string
		appProfile    string
		wantErr       bool
	}{
		"no_conditional_rules": {
			settingName: "some_setting",
			value:       "value",
			conditional: map[string]interface{}{},
			settings:    map[string]interface{}{},
			appType:     "enterprise",
			appProfile:  "http",
			wantErr:     false,
		},
		"conditional_field_not_found": {
			settingName: "some_setting",
			value:       "value",
			conditional: map[string]interface{}{
				"wapp_auth": map[string]interface{}{
					"certonly": map[string]interface{}{
						"ValidValues": []string{"none", "kerberos"},
					},
				},
			},
			settings:   map[string]interface{}{},
			appType:    "enterprise",
			appProfile: "http",
			wantErr:    false,
		},
		"valid_conditional_rule": {
			settingName: "app_auth",
			value:       "none",
			conditional: map[string]interface{}{
				"wapp_auth": map[string]interface{}{
					"certonly": map[string]interface{}{
						"ValidValues": []string{"none", "kerberos", "oidc"},
					},
				},
			},
			settings: map[string]interface{}{
				"wapp_auth": "certonly",
			},
			appType:    "enterprise",
			appProfile: "rdp",
			wantErr:    false,
		},
		"invalid_conditional_value": {
			settingName: "app_auth",
			value:       "invalid",
			conditional: map[string]interface{}{
				"wapp_auth": map[string]interface{}{
					"certonly": map[string]interface{}{
						"ValidValues": []string{"none", "kerberos"},
					},
				},
			},
			settings: map[string]interface{}{
				"wapp_auth": "certonly",
			},
			appType:    "enterprise",
			appProfile: "rdp",
			wantErr:    true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateConditionalRules(tt.settingName, tt.value, tt.conditional, tt.settings, tt.appType, tt.appProfile, logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateConditionalRules() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestApplyConditionalRules(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := map[string]struct {
		settingName string
		value       interface{}
		rules       interface{}
		wantErr     bool
	}{
		"valid_values_match": {
			settingName: "app_auth",
			value:       "none",
			rules: map[string]interface{}{
				"ValidValues": []string{"none", "kerberos"},
			},
			wantErr: false,
		},
		"valid_values_no_match": {
			settingName: "app_auth",
			value:       "invalid",
			rules: map[string]interface{}{
				"ValidValues": []string{"none", "kerberos"},
			},
			wantErr: true,
		},
		"exclude_match": {
			settingName: "app_auth",
			value:       "blocked",
			rules: map[string]interface{}{
				"Exclude": []string{"blocked"},
			},
			wantErr: true,
		},
		"exclude_no_match": {
			settingName: "app_auth",
			value:       "allowed",
			rules: map[string]interface{}{
				"Exclude": []string{"blocked"},
			},
			wantErr: false,
		},
		"multiple_exclude_values": {
			settingName: "app_auth",
			value:       "blocked1",
			rules: map[string]interface{}{
				"Exclude": []string{"blocked1", "blocked2"},
			},
			wantErr: true,
		},
		"multiple_valid_values": {
			settingName: "app_auth",
			value:       "value2",
			rules: map[string]interface{}{
				"ValidValues": []string{"value1", "value2", "value3"},
			},
			wantErr: false,
		},
		"both_validvalues_and_exclude": {
			settingName: "app_auth",
			value:       "allowed",
			rules: map[string]interface{}{
				"ValidValues": []string{"allowed", "blocked"},
				"Exclude":     []string{"blocked"},
			},
			wantErr: false,
		},
		"both_validvalues_and_exclude_match_exclude": {
			settingName: "app_auth",
			value:       "blocked",
			rules: map[string]interface{}{
				"ValidValues": []string{"allowed", "blocked"},
				"Exclude":     []string{"blocked"},
			},
			wantErr: true,
		},
		"no_rules": {
			settingName: "app_auth",
			value:       "value",
			rules:       map[string]interface{}{},
			wantErr:     false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := applyConditionalRules(tt.settingName, tt.value, tt.rules, logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("applyConditionalRules() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateIntSettingWithReflect(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := map[string]struct {
		value    interface{}
		kind     reflect.Kind
		rule     SettingRule
		wantErr  bool
	}{
		"valid_int": {
			value:   42,
			kind:     reflect.Int,
			rule:     SettingRule{MinValue: 0, MaxValue: 100},
			wantErr:  false,
		},
		"int_out_of_range": {
			value:   150,
			kind:     reflect.Int,
			rule:     SettingRule{MinValue: 0, MaxValue: 100},
			wantErr:  true,
		},
		"valid_float": {
			value:   42.5,
			kind:     reflect.Float64,
			rule:     SettingRule{MinValue: 0, MaxValue: 100},
			wantErr:  false,
		},
		"valid_string_int": {
			value:   "42",
			kind:     reflect.String,
			rule:     SettingRule{MinValue: 0, MaxValue: 100},
			wantErr:  false,
		},
		"invalid_string": {
			value:   "not-a-number",
			kind:     reflect.String,
			rule:     SettingRule{MinValue: 0, MaxValue: 100},
			wantErr:  true,
		},
		"valid_enum_string": {
			value:   "saml",
			kind:     reflect.String,
			rule:     SettingRule{ValidValues: []string{"saml", "oidc", "none"}},
			wantErr:  false,
		},
		"invalid_enum_string": {
			value:   "invalid",
			kind:     reflect.String,
			rule:     SettingRule{ValidValues: []string{"saml", "oidc", "none"}},
			wantErr:  true,
		},
		"nil_pointer_optional": {
			value:   (*int)(nil),
			kind:     reflect.Ptr,
			rule:     SettingRule{Required: false},
			wantErr:  false,
		},
		"nil_pointer_required": {
			value:   (*int)(nil),
			kind:     reflect.Ptr,
			rule:     SettingRule{Required: true},
			wantErr:  true,
		},
		"int_at_minimum": {
			value:   0,
			kind:     reflect.Int,
			rule:     SettingRule{MinValue: 0, MaxValue: 100},
			wantErr:  false,
		},
		"int_at_maximum": {
			value:   100,
			kind:     reflect.Int,
			rule:     SettingRule{MinValue: 0, MaxValue: 100},
			wantErr:  false,
		},
		"int_below_minimum": {
			value:   -1,
			kind:     reflect.Int,
			rule:     SettingRule{MinValue: 0, MaxValue: 100},
			wantErr:  true,
		},
		"int_above_maximum": {
			value:   101,
			kind:     reflect.Int,
			rule:     SettingRule{MinValue: 0, MaxValue: 100},
			wantErr:  true,
		},
		"float_below_minimum": {
			value:   -1.5,
			kind:     reflect.Float64,
			rule:     SettingRule{MinValue: 0, MaxValue: 100},
			wantErr:  true,
		},
		"float_above_maximum_truncated": {
			value:   100.5,
			kind:     reflect.Float64,
			rule:     SettingRule{MinValue: 0, MaxValue: 100},
			wantErr:  false, // 100.5 truncates to 100, which is within range
		},
		"string_int_below_minimum": {
			value:   "-1",
			kind:     reflect.String,
			rule:     SettingRule{MinValue: 0, MaxValue: 100},
			wantErr:  true,
		},
		"string_int_above_maximum": {
			value:   "101",
			kind:     reflect.String,
			rule:     SettingRule{MinValue: 0, MaxValue: 100},
			wantErr:  true,
		},
		"string_int_at_boundaries": {
			value:   "0",
			kind:     reflect.String,
			rule:     SettingRule{MinValue: 0, MaxValue: 100},
			wantErr:  false,
		},
		"enum_string_empty": {
			value:   "",
			kind:     reflect.String,
			rule:     SettingRule{ValidValues: []string{"saml", "oidc", "none"}},
			wantErr:  true,
		},
		"enum_string_case_sensitive": {
			value:   "SAML",
			kind:     reflect.String,
			rule:     SettingRule{ValidValues: []string{"saml", "oidc", "none"}},
			wantErr:  true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateIntSettingWithReflect(tt.value, tt.kind, tt.rule, logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateIntSettingWithReflect() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateCORSFields(t *testing.T) {
	tests := map[string]struct {
		settings map[string]interface{}
		appType  string
		wantErr  bool
	}{
		"cors_fields_for_non_tunnel": {
			settings: map[string]interface{}{
				"allow_cors": true,
			},
			appType: "enterprise",
			wantErr: false,
		},
		"cors_fields_for_tunnel": {
			settings: map[string]interface{}{
				"allow_cors": true,
			},
			appType: "tunnel",
			wantErr: true,
		},
		"allow_cors_true_with_required_fields": {
			settings: map[string]interface{}{
				"allow_cors":           "true",
				"cors_origin_list":     []string{"https://example.com"},
				"cors_header_list":      []string{"Content-Type"},
				"cors_method_list":      []string{"GET"},
				"cors_support_credential": true,
				"cors_max_age":         3600,
			},
			appType: "enterprise",
			wantErr: false,
		},
		"allow_cors_true_missing_required_fields": {
			settings: map[string]interface{}{
				"allow_cors": "true",
				// Missing required CORS fields
			},
			appType: "enterprise",
			wantErr: true,
		},
		"allow_cors_false": {
			settings: map[string]interface{}{
				"allow_cors": false,
			},
			appType: "enterprise",
			wantErr: false,
		},
		"allow_cors_string_false": {
			settings: map[string]interface{}{
				"allow_cors": "false",
			},
			appType: "enterprise",
			wantErr: false,
		},
		"allow_cors_true_missing_origin_list": {
			settings: map[string]interface{}{
				"allow_cors":           "true",
				"cors_header_list":      []string{"Content-Type"},
				"cors_method_list":      []string{"GET"},
				"cors_support_credential": true,
				"cors_max_age":         3600,
			},
			appType: "enterprise",
			wantErr: true,
		},
		"allow_cors_true_missing_method_list": {
			settings: map[string]interface{}{
				"allow_cors":           "true",
				"cors_origin_list":     []string{"https://example.com"},
				"cors_header_list":      []string{"Content-Type"},
				"cors_support_credential": true,
				"cors_max_age":         3600,
			},
			appType: "enterprise",
			wantErr: true,
		},
		"allow_cors_true_empty_origin_list": {
			settings: map[string]interface{}{
				"allow_cors":           "true",
				"cors_origin_list":     []string{},
				"cors_header_list":      []string{"Content-Type"},
				"cors_method_list":      []string{"GET"},
				"cors_support_credential": true,
				"cors_max_age":         3600,
			},
			appType: "enterprise",
			wantErr: false, // Function only checks if field exists, not if it's empty
		},
		"allow_cors_true_empty_method_list": {
			settings: map[string]interface{}{
				"allow_cors":           "true",
				"cors_origin_list":     []string{"https://example.com"},
				"cors_header_list":      []string{"Content-Type"},
				"cors_method_list":      []string{},
				"cors_support_credential": true,
				"cors_max_age":         3600,
			},
			appType: "enterprise",
			wantErr: false, // Function only checks if field exists, not if it's empty
		},
		"no_cors_fields": {
			settings: map[string]interface{}{},
			appType:  "enterprise",
			wantErr:  false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateCORSFields(tt.settings, tt.appType)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCORSFields() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateArraySettingWithReflect(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := map[string]struct {
		value   interface{}
		kind    reflect.Kind
		rule    SettingRule
		wantErr bool
	}{
		"valid_slice": {
			value:   []interface{}{"item1", "item2"},
			kind:     reflect.Slice,
			rule:     SettingRule{},
			wantErr:  false,
		},
		"valid_array": {
			value:   [2]string{"item1", "item2"},
			kind:     reflect.Array,
			rule:     SettingRule{},
			wantErr:  false,
		},
		"invalid_type": {
			value:   "not-an-array",
			kind:     reflect.String,
			rule:     SettingRule{},
			wantErr:  true,
		},
		"empty_slice": {
			value:   []interface{}{},
			kind:     reflect.Slice,
			rule:     SettingRule{},
			wantErr:  false,
		},
		"nil_slice": {
			value:   []interface{}(nil),
			kind:     reflect.Slice,
			rule:     SettingRule{},
			wantErr:  false,
		},
		"slice_with_int_elements": {
			value:   []interface{}{1, 2, 3},
			kind:     reflect.Slice,
			rule:     SettingRule{},
			wantErr:  false,
		},
		"slice_with_mixed_elements": {
			value:   []interface{}{"item1", 2, true},
			kind:     reflect.Slice,
			rule:     SettingRule{},
			wantErr:  false,
		},
		"empty_array": {
			value:   [0]string{},
			kind:     reflect.Array,
			rule:     SettingRule{},
			wantErr:  false,
		},
		"array_with_elements": {
			value:   [3]string{"item1", "item2", "item3"},
			kind:     reflect.Array,
			rule:     SettingRule{},
			wantErr:  false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateArraySettingWithReflect(tt.value, tt.kind, tt.rule, logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateArraySettingWithReflect() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHandleAuthConditionalRules(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := map[string]struct {
		settingName string
		value       interface{}
		settings    map[string]interface{}
		appType     string
		appProfile  string
		wantErr     bool
	}{
		"wapp_auth_certonly_rdp": {
			settingName: "wapp_auth",
			value:       "certonly",
			settings:    map[string]interface{}{},
			appType:     "enterprise",
			appProfile:  "rdp",
			wantErr:     false,
		},
		"wapp_auth_certonly_non_rdp": {
			settingName: "wapp_auth",
			value:       "certonly",
			settings:    map[string]interface{}{},
			appType:     "enterprise",
			appProfile:  "http",
			wantErr:     true,
		},
		"app_auth_with_certonly_rdp_valid": {
			settingName: "app_auth",
			value:       "none",
			settings: map[string]interface{}{
				"wapp_auth": "certonly",
			},
			appType:    "enterprise",
			appProfile: "rdp",
			wantErr:    false,
		},
		"app_auth_with_certonly_rdp_invalid": {
			settingName: "app_auth",
			value:       "saml",
			settings: map[string]interface{}{
				"wapp_auth": "certonly",
			},
			appType:    "enterprise",
			appProfile: "rdp",
			wantErr:    true,
		},
		"wapp_auth_form_allowed": {
			settingName: "wapp_auth",
			value:       "form",
			settings:    map[string]interface{}{},
			appType:     "enterprise",
			appProfile:  "http",
			wantErr:     false,
		},
		"wapp_auth_basic_allowed": {
			settingName: "wapp_auth",
			value:       "basic",
			settings:    map[string]interface{}{},
			appType:     "enterprise",
			appProfile:  "http",
			wantErr:     false,
		},
		"app_auth_with_certonly_http_valid": {
			settingName: "app_auth",
			value:       "none",
			settings: map[string]interface{}{
				"wapp_auth": "certonly",
			},
			appType:    "enterprise",
			appProfile: "http",
			wantErr:    false,
		},
		"app_auth_with_certonly_http_no_validation": {
			settingName: "app_auth",
			value:       "saml",
			settings: map[string]interface{}{
				"wapp_auth": "certonly",
			},
			appType:    "enterprise",
			appProfile: "http",
			wantErr:    false, // handleAuthConditionalRules only validates app_auth for RDP profile with certonly
		},
		"non_auth_setting": {
			settingName: "other_setting",
			value:       "value",
			settings:    map[string]interface{}{},
			appType:     "enterprise",
			appProfile:  "http",
			wantErr:     false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := handleAuthConditionalRules(tt.settingName, tt.value, tt.settings, tt.appType, tt.appProfile, logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("handleAuthConditionalRules() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

