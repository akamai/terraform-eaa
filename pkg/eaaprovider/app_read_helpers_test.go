package eaaprovider

import (
	"testing"

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
