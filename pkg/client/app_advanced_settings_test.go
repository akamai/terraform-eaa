package client

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseAdvancedSettingsAppliesCORSSupportCredentialDefault(t *testing.T) {
	advSettings, err := ParseAdvancedSettingsWithDefaults(`{}`)
	if err != nil {
		t.Fatalf("ParseAdvancedSettingsWithDefaults returned error: %v", err)
	}

	if advSettings.CORSSupportCredential != string(DefaultCORSSupportCredential) {
		t.Fatalf("CORSSupportCredential = %q, want %q", advSettings.CORSSupportCredential, string(DefaultCORSSupportCredential))
	}

	if advSettings.ExternalCookieDomain != nil {
		t.Fatalf("ExternalCookieDomain = %v, want nil", *advSettings.ExternalCookieDomain)
	}

	if advSettings.IsSSLVerificationEnabled != string(DefaultIsSSLVerificationEnabled) {
		t.Fatalf("IsSSLVerificationEnabled = %q, want %q", advSettings.IsSSLVerificationEnabled, string(DefaultIsSSLVerificationEnabled))
	}

	if advSettings.KeepaliveTimeout != string(DefaultKeepAliveTimeout) {
		t.Fatalf("KeepaliveTimeout = %q, want %q", advSettings.KeepaliveTimeout, string(DefaultKeepAliveTimeout))
	}

	if advSettings.SingleHostCookieDomain != string(DefaultSingleHostCookieDomain) {
		t.Fatalf("SingleHostCookieDomain = %q, want %q", advSettings.SingleHostCookieDomain, string(DefaultSingleHostCookieDomain))
	}
}

func TestParseAdvancedSettingsRemoteSparkSnakeCaseAliases(t *testing.T) {
	advSettings, err := ParseAdvancedSettingsWithDefaults(`{
		"remote_spark_map_clipboard": "true",
		"remote_spark_map_disk": "false",
		"remote_spark_map_printer": "true"
	}`)
	if err != nil {
		t.Fatalf("ParseAdvancedSettingsWithDefaults returned error: %v", err)
	}

	if advSettings.RemoteSparkMapClipboard != "true" {
		t.Fatalf("RemoteSparkMapClipboard = %q, want %q", advSettings.RemoteSparkMapClipboard, "true")
	}
	if advSettings.RemoteSparkMapDisk != "false" {
		t.Fatalf("RemoteSparkMapDisk = %q, want %q", advSettings.RemoteSparkMapDisk, "false")
	}
	if advSettings.RemoteSparkMapPrinter != "true" {
		t.Fatalf("RemoteSparkMapPrinter = %q, want %q", advSettings.RemoteSparkMapPrinter, "true")
	}

	var complete AdvancedSettingsComplete
	UpdateAdvancedSettings(&complete, advSettings)

	payload, err := json.Marshal(complete)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}

	payloadStr := string(payload)
	for _, key := range []string{"remote_spark_mapClipboard", "remote_spark_mapDisk", "remote_spark_mapPrinter"} {
		if !strings.Contains(payloadStr, `"`+key+`"`) {
			t.Fatalf("payload %s missing API key %q", payloadStr, key)
		}
	}

	for _, key := range []string{"remote_spark_map_clipboard", "remote_spark_map_disk", "remote_spark_map_printer"} {
		if strings.Contains(payloadStr, `"`+key+`"`) {
			t.Fatalf("payload %s unexpectedly contains HCL alias key %q", payloadStr, key)
		}
	}
}

func TestParseAdvancedSettingsAppliesPointerStringFields(t *testing.T) {
	advSettings, err := ParseAdvancedSettingsWithDefaults(`{
		"external_cookie_domain": "",
		"login_url": null,
		"user_name": "alice"
	}`)
	if err != nil {
		t.Fatalf("ParseAdvancedSettingsWithDefaults returned error: %v", err)
	}

	if advSettings.ExternalCookieDomain == nil {
		t.Fatal("ExternalCookieDomain = nil, want non-nil pointer to empty string")
	}
	if *advSettings.ExternalCookieDomain != "" {
		t.Fatalf("ExternalCookieDomain = %q, want empty string", *advSettings.ExternalCookieDomain)
	}

	if advSettings.LoginURL != nil {
		t.Fatalf("LoginURL = %v, want nil", *advSettings.LoginURL)
	}

	if advSettings.UserName == nil {
		t.Fatal("UserName = nil, want non-nil pointer")
	}
	if *advSettings.UserName != "alice" {
		t.Fatalf("UserName = %q, want %q", *advSettings.UserName, "alice")
	}
}
