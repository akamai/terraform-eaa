package logging

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiagError(t *testing.T) {
	err := Errorf([]Tag{TagAPI, TagApp}, "create failed")
	diags := DiagError(err)

	require.Len(t, diags, 1)
	assert.Equal(t, diag.Error, diags[0].Severity)
	assert.Equal(t, "[API][APP] create failed", diags[0].Summary)
}

func TestDiagError_WithWrapped(t *testing.T) {
	inner := fmt.Errorf("connection refused")
	err := Wrapf(inner, []Tag{TagAPI}, "request failed")
	diags := DiagError(err)

	require.Len(t, diags, 1)
	assert.Equal(t, diag.Error, diags[0].Severity)
	assert.Equal(t, "[API] request failed", diags[0].Summary)
	assert.NotContains(t, diags[0].Summary, "connection refused")
	assert.Equal(t, "connection refused", diags[0].Detail)
}

func TestDiagError_Nil(t *testing.T) {
	diags := DiagError(nil)
	assert.Nil(t, diags)
}

func TestDiagWarning(t *testing.T) {
	err := Errorf([]Tag{TagProvider}, "deprecated field")
	diags := DiagWarning(err)

	require.Len(t, diags, 1)
	assert.Equal(t, diag.Warning, diags[0].Severity)
	assert.Contains(t, diags[0].Summary, "deprecated field")
}

func TestDiagWarning_Nil(t *testing.T) {
	diags := DiagWarning(nil)
	assert.Nil(t, diags)
}

func TestDiagErrorf(t *testing.T) {
	diags := DiagErrorf([]Tag{TagAPI, TagCreate}, "failed to create %s", "pool")

	require.Len(t, diags, 1)
	assert.Equal(t, diag.Error, diags[0].Severity)
	assert.Equal(t, "[API][CREATE] failed to create pool", diags[0].Summary)
}

func TestDiagWarningf(t *testing.T) {
	diags := DiagWarningf([]Tag{TagConfig}, "field %q is deprecated", "old_field")

	require.Len(t, diags, 1)
	assert.Equal(t, diag.Warning, diags[0].Severity)
	assert.Contains(t, diags[0].Summary, `"old_field"`)
}

func TestDiagFromErr(t *testing.T) {
	inner := fmt.Errorf("connection refused")
	diags := DiagFromErr(inner, []Tag{TagAPI, TagApp}, "API call failed")

	require.Len(t, diags, 1)
	assert.Equal(t, diag.Error, diags[0].Severity)
	assert.Equal(t, "[API][APP] API call failed", diags[0].Summary)
	assert.NotContains(t, diags[0].Summary, "connection refused")
	assert.Equal(t, "connection refused", diags[0].Detail)
}

func TestDiagFromErr_NilError(t *testing.T) {
	diags := DiagFromErr(nil, []Tag{TagAPI}, "no underlying cause")

	require.Len(t, diags, 1)
	assert.Equal(t, diag.Error, diags[0].Severity)
	assert.Contains(t, diags[0].Summary, "no underlying cause")
	assert.NotContains(t, diags[0].Summary, "<nil>")
}

func TestDiagFromErrf(t *testing.T) {
	inner := fmt.Errorf("timeout")
	diags := DiagFromErrf(inner, []Tag{TagAPI}, "request to %s failed", "/apps")

	require.Len(t, diags, 1)
	assert.Equal(t, diag.Error, diags[0].Severity)
	assert.Equal(t, "[API] request to /apps failed", diags[0].Summary)
	assert.NotContains(t, diags[0].Summary, "timeout")
	assert.Equal(t, "timeout", diags[0].Detail)
}

func TestDiagFromErrf_NilError(t *testing.T) {
	diags := DiagFromErrf(nil, []Tag{TagAPI}, "no underlying cause")

	require.Len(t, diags, 1)
	assert.Equal(t, diag.Error, diags[0].Severity)
	assert.Contains(t, diags[0].Summary, "no underlying cause")
	assert.NotContains(t, diags[0].Summary, "<nil>")
}

func TestDiagError_AcceptsPlainError(t *testing.T) {
	err := fmt.Errorf("plain error without tags")
	diags := DiagError(err)

	require.Len(t, diags, 1)
	assert.Equal(t, diag.Error, diags[0].Severity)
	assert.Equal(t, "plain error without tags", diags[0].Summary)
	assert.Empty(t, diags[0].Detail)
}
