package eaaprovider

import (
	"testing"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// derefStr
// ---------------------------------------------------------------------------

func TestDerefStr_NilPointer(t *testing.T) {
	got := derefStr(nil)
	assert.Equal(t, "", got)
}

func TestDerefStr_NonNilPointer(t *testing.T) {
	s := "hello"
	got := derefStr(&s)
	assert.Equal(t, "hello", got)
}

func TestDerefStr_EmptyString(t *testing.T) {
	s := ""
	got := derefStr(&s)
	assert.Equal(t, "", got)
}

// ---------------------------------------------------------------------------
// serverComputedAdvancedSettingsKeys
// ---------------------------------------------------------------------------

func TestServerComputedAdvancedSettingsKeys(t *testing.T) {
	expectedKeys := []string{
		"g2o_key",
		"g2o_nonce",
		"edge_cookie_key",
		"sla_object_url",
		"edge_transport_property_id",
	}

	for _, key := range expectedKeys {
		assert.True(t, serverComputedAdvancedSettingsKeys[key],
			"expected %q to be in serverComputedAdvancedSettingsKeys", key)
	}

	assert.False(t, serverComputedAdvancedSettingsKeys["acceleration"],
		"acceleration should not be in serverComputedAdvancedSettingsKeys")
}

// ---------------------------------------------------------------------------
// mapAdvancedSettingsFromResponse
// ---------------------------------------------------------------------------

func TestMapAdvancedSettingsFromResponse(t *testing.T) {
	t.Run("preserves_only_existing_keys_on_read", func(t *testing.T) {
		d := createTestApplicationResourceData(t, map[string]interface{}{
			"advanced_settings": map[string]interface{}{
				"websocket_enabled": "true",
			},
		})
		d.SetId("test-app-uuid")

		appResp := &client.ApplicationResponse{
			AdvancedSettings: client.AdvancedSettingsComplete{
				WebSocketEnabled:        "false",
				KeepaliveConnectionPool: "30",
			},
		}

		diags := mapAdvancedSettingsFromResponse(d, appResp)
		assert.Empty(t, diags)

		settings := d.Get("advanced_settings").(map[string]interface{})
		assert.Equal(t, "false", settings["websocket_enabled"], "existing key should be updated")
		_, hasKeepalive := settings["keepalive_connection_pool"]
		assert.False(t, hasKeepalive, "key not in prior state should not appear")
	})

	t.Run("surfaces_all_nonempty_values_on_import", func(t *testing.T) {
		d := createTestApplicationResourceData(t, map[string]interface{}{})
		d.SetId("test-app-uuid")

		appResp := &client.ApplicationResponse{
			AdvancedSettings: client.AdvancedSettingsComplete{
				WebSocketEnabled:        "true",
				KeepaliveConnectionPool: "30",
			},
		}

		diags := mapAdvancedSettingsFromResponse(d, appResp)
		assert.Empty(t, diags)

		settings := d.Get("advanced_settings").(map[string]interface{})
		assert.Equal(t, "true", settings["websocket_enabled"])
		assert.Equal(t, "30", settings["keepalive_connection_pool"])
	})
}
