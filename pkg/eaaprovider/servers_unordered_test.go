package eaaprovider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/require"
)

// Origin servers are a load-balanced pool: the EAA API returns them in an
// arbitrary order, so the schema must treat [A,B] and [B,A] as equal to avoid a
// perpetual `terraform plan` diff. This requires the "servers" attribute to be a
// TypeSet whose hash ignores the API-computed orig_tls field.
func TestServersAttributeIsUnordered(t *testing.T) {
	serversSchema := resourceEaaApplication().Schema["servers"]

	require.Equal(t, schema.TypeSet, serversSchema.Type,
		"servers must be a TypeSet so origin order does not produce a diff")
	require.NotNil(t, serversSchema.Set, "servers must define a Set hash function")

	hash := serversSchema.Set
	serverA := map[string]interface{}{
		"origin_host": "10.114.11.11", "origin_port": 443, "origin_protocol": "https", "orig_tls": true,
	}
	serverB := map[string]interface{}{
		"origin_host": "10.114.11.12", "origin_port": 443, "origin_protocol": "https", "orig_tls": true,
	}

	configOrder := schema.NewSet(hash, []interface{}{serverA, serverB})
	apiOrder := schema.NewSet(hash, []interface{}{serverB, serverA})
	require.True(t, configOrder.Equal(apiOrder),
		"reordered servers must be equal: [A,B] vs [B,A] should not diff")

	// orig_tls is Optional+Computed (derived by the API). It must not affect the
	// hash, otherwise an unset config value vs an API-populated state value would
	// reintroduce the very diff this fix removes.
	withTLS := map[string]interface{}{
		"origin_host": "10.114.11.11", "origin_port": 443, "origin_protocol": "https", "orig_tls": true,
	}
	withoutTLS := map[string]interface{}{
		"origin_host": "10.114.11.11", "origin_port": 443, "origin_protocol": "https", "orig_tls": false,
	}
	require.Equal(t, hash(withTLS), hash(withoutTLS),
		"orig_tls must be excluded from the servers hash")
}
