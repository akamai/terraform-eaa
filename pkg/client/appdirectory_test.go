package client

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssignIdpDirectory(t *testing.T) {
	enableMFA := true
	tests := map[string]struct {
		errIs   error
		handler http.HandlerFunc
		appDir  AppDirectory
		wantErr bool
	}{
		"success": {
			appDir:  AppDirectory{APP_ID: "app-uuid-1", UUID: "dir-uuid-1", EnableMFA: &enableMFA},
			handler: jsonHandler(http.StatusOK, nil),
		},
		"empty_app_id": {
			appDir:  AppDirectory{APP_ID: "", UUID: "dir-uuid-1"},
			handler: jsonHandler(http.StatusOK, nil),
			wantErr: true,
			errIs:   ErrAssignDirectoryFailure,
		},
		"empty_uuid": {
			appDir:  AppDirectory{APP_ID: "app-uuid-1", UUID: ""},
			handler: jsonHandler(http.StatusOK, nil),
			wantErr: true,
			errIs:   ErrAssignDirectoryFailure,
		},
		"api_error": {
			appDir:  AppDirectory{APP_ID: "app-uuid-1", UUID: "dir-uuid-1"},
			handler: errorJSONHandler(http.StatusInternalServerError, "assign failed"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)

			err := tt.appDir.AssignIdpDirectory(context.Background(), ec)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errIs != nil {
					assert.ErrorIs(t, err, tt.errIs)
				}
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestGetIdpDirectoryGroup(t *testing.T) {
	dirData := &DirectoryData{
		Name: "test-dir",
		UUID: "dir-uuid-1",
		Groups: []GroupData{
			{Name: "group-a", UUID_URL: "group-uuid-a"},
			{Name: "group-b", UUID_URL: "group-uuid-b"},
		},
	}

	tests := map[string]struct {
		wantGroup *GroupData
		groupName string
		wantErr   bool
	}{
		"found": {
			groupName: "group-a",
			wantGroup: &GroupData{Name: "group-a", UUID_URL: "group-uuid-a"},
		},
		"not_found": {
			groupName: "group-missing",
			wantErr:   true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// GetIdpDirectoryGroup doesn't use the client, but still needs one for logger
			ec := newTestClient(t, jsonHandler(http.StatusOK, nil))

			got, err := dirData.GetIdpDirectoryGroup(context.Background(), ec, tt.groupName)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantGroup, got)
		})
	}
}

func TestAssignIdpDirectoryGroups(t *testing.T) {
	tests := map[string]struct {
		dirData       *DirectoryData
		handler       http.HandlerFunc
		appGroupsList []interface{}
		wantErr       bool
	}{
		"success_with_groups": {
			dirData: &DirectoryData{
				Name: "test-dir",
				UUID: "dir-uuid-1",
				Groups: []GroupData{
					{Name: "group-a", UUID_URL: "group-uuid-a"},
					{Name: "group-b", UUID_URL: "group-uuid-b"},
				},
			},
			appGroupsList: []interface{}{
				map[string]interface{}{"name": "group-a", "enable_mfa": "inherit"},
			},
			handler: jsonHandler(http.StatusOK, nil),
		},
		"empty_groups_list": {
			dirData: &DirectoryData{
				Name:   "test-dir",
				UUID:   "dir-uuid-1",
				Groups: []GroupData{},
			},
			appGroupsList: []interface{}{},
			handler:       jsonHandler(http.StatusOK, nil),
			wantErr:       false, // returns nil when no groups
		},
		"no_matching_groups": {
			dirData: &DirectoryData{
				Name: "test-dir",
				UUID: "dir-uuid-1",
				Groups: []GroupData{
					{Name: "group-a", UUID_URL: "group-uuid-a"},
				},
			},
			appGroupsList: []interface{}{
				map[string]interface{}{"name": "missing-group"},
			},
			handler: jsonHandler(http.StatusOK, nil),
			wantErr: false, // skips not-found groups, ends up empty
		},
		"api_error": {
			dirData: &DirectoryData{
				Name: "test-dir",
				UUID: "dir-uuid-1",
				Groups: []GroupData{
					{Name: "group-a", UUID_URL: "group-uuid-a"},
				},
			},
			appGroupsList: []interface{}{
				map[string]interface{}{"name": "group-a"},
			},
			handler: errorJSONHandler(http.StatusInternalServerError, "assign failed"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)

			err := tt.dirData.AssignIdpDirectoryGroups(context.Background(), ec, "app-uuid-1", tt.appGroupsList)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestAssignAllDirectoryGroups(t *testing.T) {
	tests := map[string]struct {
		dirData *DirectoryData
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			dirData: &DirectoryData{
				Name: "test-dir",
				UUID: "dir-uuid-1",
				Groups: []GroupData{
					{Name: "group-a", UUID_URL: "group-uuid-a"},
					{Name: "group-b", UUID_URL: "group-uuid-b"},
				},
			},
			handler: jsonHandler(http.StatusOK, nil),
		},
		"empty_groups": {
			dirData: &DirectoryData{
				Name:   "test-dir",
				UUID:   "dir-uuid-1",
				Groups: []GroupData{},
			},
			handler: jsonHandler(http.StatusOK, nil),
			wantErr: false, // returns nil when no groups
		},
		"api_error": {
			dirData: &DirectoryData{
				Name: "test-dir",
				UUID: "dir-uuid-1",
				Groups: []GroupData{
					{Name: "group-a", UUID_URL: "group-uuid-a"},
				},
			},
			handler: errorJSONHandler(http.StatusInternalServerError, "assign failed"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)

			err := tt.dirData.AssignAllDirectoryGroups(context.Background(), ec, "app-uuid-1")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
