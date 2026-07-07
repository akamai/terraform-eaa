package client

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListDirectories(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
		wantLen int
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, DirectoryListResponse{
				Objects: []DirectoryListEntry{
					{Name: "Cloud Directory", UUIDURL: "abc123", Service: 6, Status: 1, DirectoryType: 1, UserCount: 10, GroupCount: 2},
					{Name: "AD Directory", UUIDURL: "def456", Service: 1, Status: 1, DirectoryType: 2, UserCount: 50, GroupCount: 5},
				},
			}),
			wantLen: 2,
		},
		"skips_empty_names": {
			handler: jsonHandler(http.StatusOK, DirectoryListResponse{
				Objects: []DirectoryListEntry{
					{Name: "", UUIDURL: "abc123", Service: 6},
					{Name: "Valid", UUIDURL: "def456", Service: 1},
				},
			}),
			wantLen: 1,
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "server error"),
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			dirs, err := ListDirectories(context.Background(), ec)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, dirs, tt.wantLen)
		})
	}
}

func TestGetDirectoryByName(t *testing.T) {
	handler := jsonHandler(http.StatusOK, DirectoryListResponse{
		Objects: []DirectoryListEntry{
			{Name: "Cloud Directory", UUIDURL: "abc123", Service: 6},
			{Name: "AD Directory", UUIDURL: "def456", Service: 1},
		},
	})

	tests := map[string]struct {
		errIs   error
		name    string
		wantErr bool
	}{
		"found": {
			name: "Cloud Directory",
		},
		"not_found": {
			name:    "Nonexistent",
			wantErr: true,
			errIs:   ErrDirectoryNotFound,
		},
	}

	for testName, tt := range tests {
		t.Run(testName, func(t *testing.T) {
			ec := newTestClient(t, handler)
			dir, err := GetDirectoryByName(context.Background(), ec, tt.name)
			if requireErrIs(t, err, tt.wantErr, tt.errIs) {
				return
			}
			require.NotNil(t, dir)
			assert.Equal(t, tt.name, dir.Name)
		})
	}
}
