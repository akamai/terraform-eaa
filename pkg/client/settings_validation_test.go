package client

import (
	"reflect"
	"testing"

	"github.com/hashicorp/go-hclog"
)

func TestSettingsRuleDefaultsMatchUpdatedSharedDefaults(t *testing.T) {
	if SETTINGS_RULES["session_sticky"].Default != DefaultSessionSticky {
		t.Fatalf("session_sticky default = %v, want %v", SETTINGS_RULES["session_sticky"].Default, DefaultSessionSticky)
	}

	if !reflect.DeepEqual(SETTINGS_RULES["external_cookie_domain"].Default, DefaultExternalCookieDomain) {
		t.Fatalf("external_cookie_domain default = %v, want ''", SETTINGS_RULES["external_cookie_domain"].Default)
	}
}

func TestValidateSettingSkipsEquivalentNumericDefault(t *testing.T) {
	rule := SETTINGS_RULES["x_wapp_pool_timeout"]

	err := validateSetting(
		"x_wapp_pool_timeout",
		float64(DefaultXWappPoolTimeout),
		&rule,
		map[string]interface{}{},
		string(ClientAppTypeTunnel),
		string(AppProfileTCP),
		hclog.NewNullLogger(),
	)
	if err != nil {
		t.Fatalf("validateSetting returned error for equivalent numeric default: %v", err)
	}
}

func TestSettingValueMatchesDefaultNumericTypes(t *testing.T) {
	if !settingValueMatchesDefault(120, float64(120)) {
		t.Fatal("expected int and float64 representations of the same number to match")
	}

	if settingValueMatchesDefault(120, float64(121)) {
		t.Fatal("expected different numeric values not to match")
	}
}

func TestSettingValueMatchesDefaultTypedString(t *testing.T) {
	if !settingValueMatchesDefault(DefaultRemoteSparkMapClipboard, "on") {
		t.Fatal("expected typed string default and plain string value to match")
	}

	if settingValueMatchesDefault(DefaultRemoteSparkMapClipboard, "off") {
		t.Fatal("expected different string values not to match")
	}
}

func TestValidateSettingSkipsEmptyOptionalCollection(t *testing.T) {
	rule := SETTINGS_RULES["rdp_remote_apps"]

	err := validateSetting(
		"rdp_remote_apps",
		[]interface{}{},
		&rule,
		map[string]interface{}{},
		string(ClientAppTypeEnterprise),
		string(AppProfileHTTP),
		hclog.NewNullLogger(),
	)
	if err != nil {
		t.Fatalf("validateSetting returned error for empty optional collection: %v", err)
	}
}
