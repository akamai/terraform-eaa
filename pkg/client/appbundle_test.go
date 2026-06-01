package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testBundles = []AppBundle{
	{Name: "bundle-a", UUIDURL: "/appbundle/uuid-a"},
	{Name: "bundle-b", UUIDURL: "/appbundle/uuid-b"},
}

func TestGetAppBundles(t *testing.T) {
	ec := newTestClient(t, jsonHandler(http.StatusOK, AppBundleResponse{Objects: testBundles}))

	resp, err := ec.GetAppBundles()
	require.NoError(t, err)
	assert.Len(t, resp.Objects, 2)
	assert.Equal(t, "bundle-a", resp.Objects[0].Name)
}

func TestGetAppBundleByName(t *testing.T) {
	tests := map[string]struct {
		name          string
		wantUUID      string
		wantErrSubstr string
	}{
		"match_first":           {name: "bundle-a", wantUUID: "/appbundle/uuid-a"},
		"match_second":          {name: "bundle-b", wantUUID: "/appbundle/uuid-b"},
		"not_found":             {name: "bundle-c", wantErrSubstr: "not found"},
		"partial_name_no_match": {name: "bundle", wantErrSubstr: "not found"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, jsonHandler(http.StatusOK, AppBundleResponse{Objects: testBundles}))

			got, err := ec.GetAppBundleByName(tt.name)
			if tt.wantErrSubstr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrSubstr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantUUID, got)
		})
	}
}

func TestGetAppBundleNameByUUID(t *testing.T) {
	tests := map[string]struct {
		uuid          string
		wantName      string
		wantErrSubstr string
	}{
		"match_first":  {uuid: "/appbundle/uuid-a", wantName: "bundle-a"},
		"match_second": {uuid: "/appbundle/uuid-b", wantName: "bundle-b"},
		"not_found":    {uuid: "/appbundle/uuid-c", wantErrSubstr: "not found"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, jsonHandler(http.StatusOK, AppBundleResponse{Objects: testBundles}))

			got, err := ec.GetAppBundleNameByUUID(tt.uuid)
			if tt.wantErrSubstr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrSubstr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantName, got)
		})
	}
}

func TestValidateAppBundleName(t *testing.T) {
	tests := map[string]struct {
		name    string
		wantErr bool
	}{
		"valid":   {name: "bundle-a", wantErr: false},
		"invalid": {name: "nonexistent", wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, jsonHandler(http.StatusOK, AppBundleResponse{Objects: testBundles}))

			err := ec.ValidateAppBundleName(tt.name)
			requireErr(t, err, tt.wantErr)
		})
	}
}
