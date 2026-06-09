package logging

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMergeFields_SourceTags(t *testing.T) {
	for _, tag := range []Tag{TagAPI, TagProvider, TagConfig} {
		t.Run(string(tag), func(t *testing.T) {
			fields := mergeFields([]Tag{tag})
			assert.Equal(t, string(tag), fields["source"])
			assert.NotContains(t, fields, "operation")
			assert.NotContains(t, fields, "resource")
		})
	}
}

func TestMergeFields_OperationTags(t *testing.T) {
	for _, tag := range []Tag{TagCreate, TagRead, TagUpdate, TagDelete, TagValidate, TagAssign, TagDeploy, TagList, TagMarshal, TagAuth} {
		t.Run(string(tag), func(t *testing.T) {
			fields := mergeFields([]Tag{tag})
			assert.Equal(t, string(tag), fields["operation"])
			assert.NotContains(t, fields, "source")
			assert.NotContains(t, fields, "resource")
		})
	}
}

func TestMergeFields_ResourceTags(t *testing.T) {
	for _, tag := range []Tag{TagApp, TagConnector, TagConnPool, TagIDP, TagCert, TagAppService, TagAgent, TagDirectory, TagAppBundle, TagCipher, TagPopTraffic} {
		t.Run(string(tag), func(t *testing.T) {
			fields := mergeFields([]Tag{tag})
			assert.Equal(t, string(tag), fields["resource"])
			assert.NotContains(t, fields, "unknown_tag")
		})
	}
}

func TestMergeFields_UnknownTag(t *testing.T) {
	fields := mergeFields([]Tag{Tag("MYSTERY")})
	assert.Equal(t, "MYSTERY", fields["resource"])
	assert.Equal(t, "MYSTERY", fields["unknown_tag"])
}

func TestMergeFields_MixedTags(t *testing.T) {
	fields := mergeFields([]Tag{TagAPI, TagCreate, TagApp})
	assert.Equal(t, "API", fields["source"])
	assert.Equal(t, "CREATE", fields["operation"])
	assert.Equal(t, "APP", fields["resource"])
}

func TestMergeFields_ExtraMaps(t *testing.T) {
	extra := map[string]any{"url": "/api/v1", "status": 200}
	fields := mergeFields([]Tag{TagAPI}, extra)

	assert.Equal(t, "API", fields["source"])
	assert.Equal(t, "/api/v1", fields["url"])
	assert.Equal(t, 200, fields["status"])
}

func TestMergeFields_TagsOverrideExtra(t *testing.T) {
	extra := map[string]any{"source": "custom"}
	fields := mergeFields([]Tag{TagAPI}, extra)

	assert.Equal(t, "API", fields["source"], "tags should override extra maps")
}

func TestMergeFields_EmptyInputs(t *testing.T) {
	fields := mergeFields(nil)
	assert.Empty(t, fields)

	fields = mergeFields([]Tag{})
	assert.Empty(t, fields)
}

func TestMergeFields_MultipleExtraMaps(t *testing.T) {
	m1 := map[string]any{"a": 1, "b": 2}
	m2 := map[string]any{"b": 3, "c": 4}
	fields := mergeFields(nil, m1, m2)

	assert.Equal(t, 1, fields["a"])
	assert.Equal(t, 3, fields["b"], "later maps should override earlier")
	assert.Equal(t, 4, fields["c"])
}

func TestMergeFields_AllTagsClassified(t *testing.T) {
	allTags := []Tag{
		TagAPI, TagProvider, TagConfig,
		TagApp, TagConnector, TagConnPool, TagIDP, TagCert, TagAppService,
		TagAgent, TagDirectory, TagAppBundle, TagCipher, TagPopTraffic,
		TagCreate, TagRead, TagUpdate, TagDelete, TagValidate, TagAssign,
		TagDeploy, TagList, TagMarshal, TagAuth,
	}
	for _, tag := range allTags {
		t.Run(string(tag), func(t *testing.T) {
			fields := mergeFields([]Tag{tag})
			_, hasSource := fields["source"]
			_, hasOperation := fields["operation"]
			_, hasResource := fields["resource"]
			assert.True(t, hasSource || hasOperation || hasResource,
				"tag %q should be classified as source, operation, or resource", tag)
			assert.NotContains(t, fields, "unknown_tag",
				"tag %q should not produce unknown_tag", tag)
		})
	}
}

func TestMergeFields_DuplicateSourceLastWins(t *testing.T) {
	fields := mergeFields([]Tag{TagAPI, TagProvider})
	assert.Equal(t, "PROVIDER", fields["source"], "last source tag should win")
}

func TestMergeFields_DuplicateOperationLastWins(t *testing.T) {
	fields := mergeFields([]Tag{TagCreate, TagUpdate})
	assert.Equal(t, "UPDATE", fields["operation"], "last operation tag should win")
}

func TestFormatLogMessage_WithoutTags(t *testing.T) {
	assert.Equal(t, "hello", formatLogMessage("hello", nil))
	assert.Equal(t, "hello", formatLogMessage("hello", []Tag{}))
}

func TestFormatLogMessage_WithTags(t *testing.T) {
	assert.Equal(t, "[API][READ] hello", formatLogMessage("hello", []Tag{TagAPI, TagRead}))
}
