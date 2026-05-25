package client

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestSetAdvancedSettingsReturnsErrorOnNilSettings(t *testing.T) {
	resourceSchema := map[string]*schema.Schema{
		"advanced_settings": {
			Type:     schema.TypeMap,
			Optional: true,
		},
	}

	d := schema.TestResourceDataRaw(t, resourceSchema, map[string]interface{}{})

	err := SetAdvancedSettings(d, nil)
	if err == nil {
		t.Fatal("SetAdvancedSettings returned nil error, want non-nil")
	}

	if !strings.Contains(err.Error(), "advanced settings cannot be nil") {
		t.Fatalf("SetAdvancedSettings error = %q, want message containing %q", err.Error(), "advanced settings cannot be nil")
	}
}

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

func TestAdvancedSettingsFromBlockDecodesFormPostAttributes(t *testing.T) {
	block := map[string]interface{}{
		"form_post_attributes": `["attr1","attr2"]`,
	}
	got, err := advancedSettingsFromBlock(block)
	if err != nil {
		t.Fatalf("advancedSettingsFromBlock returned error: %v", err)
	}
	if len(got.FormPostAttributes) != 2 || got.FormPostAttributes[0] != "attr1" || got.FormPostAttributes[1] != "attr2" {
		t.Fatalf("FormPostAttributes = %v, want [attr1 attr2]", got.FormPostAttributes)
	}
}

func TestAdvancedSettingsFromBlockEmptyFormPostAttributes(t *testing.T) {
	block := map[string]interface{}{
		"form_post_attributes": "",
	}
	got, err := advancedSettingsFromBlock(block)
	if err != nil {
		t.Fatalf("advancedSettingsFromBlock returned error: %v", err)
	}
	if got.FormPostAttributes == nil {
		t.Fatal("FormPostAttributes = nil, want empty slice")
	}
}

func TestAdvancedSettingsFromBlockErrorOnInvalidFormPostAttributes(t *testing.T) {
	block := map[string]interface{}{
		"form_post_attributes": `not-json`,
	}
	_, err := advancedSettingsFromBlock(block)
	if err == nil {
		t.Fatal("expected error for invalid form_post_attributes JSON, got nil")
	}
	if !strings.Contains(err.Error(), "invalid form_post_attributes JSON") {
		t.Fatalf("error = %q, want message containing %q", err.Error(), "invalid form_post_attributes JSON")
	}
}

func TestAdvancedSettingsFromBlockDecodesCustomHeaders(t *testing.T) {
	block := map[string]interface{}{
		"custom_headers": `[{"attribute_type":"static","header":"X-Foo","attribute":"bar"}]`,
	}
	got, err := advancedSettingsFromBlock(block)
	if err != nil {
		t.Fatalf("advancedSettingsFromBlock returned error: %v", err)
	}
	if len(got.CustomHeaders) != 1 {
		t.Fatalf("CustomHeaders len = %d, want 1", len(got.CustomHeaders))
	}
	h := got.CustomHeaders[0]
	if h.AttributeType != "static" || h.Header != "X-Foo" || h.Attribute != "bar" {
		t.Fatalf("CustomHeaders[0] = %+v, want {static X-Foo bar}", h)
	}
}

func TestAdvancedSettingsFromBlockErrorOnInvalidCustomHeaders(t *testing.T) {
	block := map[string]interface{}{
		"custom_headers": `{bad json`,
	}
	_, err := advancedSettingsFromBlock(block)
	if err == nil {
		t.Fatal("expected error for invalid custom_headers JSON, got nil")
	}
	if !strings.Contains(err.Error(), "invalid custom_headers JSON") {
		t.Fatalf("error = %q, want message containing %q", err.Error(), "invalid custom_headers JSON")
	}
}

func TestAdvancedSettingsFromBlockDecodesRequestParameters(t *testing.T) {
	block := map[string]interface{}{
		"request_parameters": `{"key":"value"}`,
	}
	got, err := advancedSettingsFromBlock(block)
	if err != nil {
		t.Fatalf("advancedSettingsFromBlock returned error: %v", err)
	}
	if got.RequestParameters == nil {
		t.Fatal("RequestParameters = nil, want non-nil pointer")
	}
	if *got.RequestParameters != `{"key":"value"}` {
		t.Fatalf("RequestParameters = %q, want %q", *got.RequestParameters, `{"key":"value"}`)
	}
}

func TestAdvancedSettingsFromBlockDecodesRDPRemoteApps(t *testing.T) {
	block := map[string]interface{}{
		"rdp_remote_apps": `[{"remote_app":"notepad","remote_app_args":"/f","remote_app_dir":"C:\\"}]`,
	}
	got, err := advancedSettingsFromBlock(block)
	if err != nil {
		t.Fatalf("advancedSettingsFromBlock returned error: %v", err)
	}
	if len(got.RDPRemoteApps) != 1 {
		t.Fatalf("RDPRemoteApps len = %d, want 1", len(got.RDPRemoteApps))
	}
	app := got.RDPRemoteApps[0]
	if app.RemoteApp != "notepad" || app.RemoteAppArgs != "/f" {
		t.Fatalf("RDPRemoteApps[0] = %+v, want {notepad /f ...}", app)
	}
}

func TestAdvancedSettingsFromBlockErrorOnInvalidRDPRemoteApps(t *testing.T) {
	block := map[string]interface{}{
		"rdp_remote_apps": `not-json`,
	}
	_, err := advancedSettingsFromBlock(block)
	if err == nil {
		t.Fatal("expected error for invalid rdp_remote_apps JSON, got nil")
	}
	if !strings.Contains(err.Error(), "invalid rdp_remote_apps JSON") {
		t.Fatalf("error = %q, want message containing %q", err.Error(), "invalid rdp_remote_apps JSON")
	}
}

func TestAdvancedSettingsFromBlockStripsTLSKeys(t *testing.T) {
	block := map[string]interface{}{
		"tls_suite_type": "1",
		"tls_suite_name": "tls-1-2",
		"acceleration":   "true",
	}
	got, err := advancedSettingsFromBlock(block)
	if err != nil {
		t.Fatalf("advancedSettingsFromBlock returned error: %v", err)
	}
	// TLS keys are stripped — they must not land in ExtraFields.
	if got.ExtraFields != nil {
		if _, hasTLSType := got.ExtraFields["tls_suite_type"]; hasTLSType {
			t.Fatal("tls_suite_type should not appear in ExtraFields")
		}
		if _, hasTLSName := got.ExtraFields["tls_suite_name"]; hasTLSName {
			t.Fatal("tls_suite_name should not appear in ExtraFields")
		}
	}
	if got.Acceleration != "true" {
		t.Fatalf("Acceleration = %q, want true", got.Acceleration)
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
