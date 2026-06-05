package eaaprovider

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResourceEaaConnectorSchemaBasics(t *testing.T) {
	r := resourceEaaConnector()
	require.NotNil(t, r)

	assert.NotNil(t, r.CreateContext)
	assert.NotNil(t, r.ReadContext)
	assert.NotNil(t, r.UpdateContext)
	assert.NotNil(t, r.DeleteContext)
	require.NotNil(t, r.Importer)
	assert.NotNil(t, r.Importer.StateContext)

	assert.True(t, r.Schema["name"].Required)
	assert.True(t, r.Schema["package"].Required)
	assert.NotNil(t, r.Schema["package"].ValidateFunc)
	assert.True(t, r.Schema["uuid_url"].Computed)
}

func TestResourceEaaConnectorRejectsAWSClassic(t *testing.T) {
	ctx := context.Background()

	t.Run("create_rejects_aws_classic", func(t *testing.T) {
		d := createTestResourceDataFor(t, resourceEaaConnector, map[string]any{
			"name":    "conn-1",
			"package": "aws_classic",
		})

		diags := resourceEaaConnectorCreate(ctx, d, nil)
		require.True(t, diags.HasError())
		assert.Contains(t, diags[0].Summary, "aws_classic")
	})
}
