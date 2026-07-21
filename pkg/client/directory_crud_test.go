package client

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateDirectory(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		req     DirectoryCreateRequest
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, DirectoryFullResponse{
				Name:    "test-dir",
				UUIDURL: "dir-uuid-123",
			}),
			req: DirectoryCreateRequest{Name: "test-dir", Service: 1},
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "create failed"),
			req:     DirectoryCreateRequest{Name: "test-dir", Service: 1},
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			resp, err := CreateDirectory(context.Background(), ec, &tt.req)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "test-dir", resp.Name)
			assert.Equal(t, "dir-uuid-123", resp.UUIDURL)
		})
	}
}

func TestGetDirectory(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, DirectoryFullResponse{
				Name:    "test-dir",
				UUIDURL: "dir-uuid-123",
				Service: 1,
			}),
		},
		"not_found": {
			handler: errorJSONHandler(http.StatusNotFound, "not found"),
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			resp, err := GetDirectory(context.Background(), ec, "dir-uuid-123")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "test-dir", resp.Name)
		})
	}
}

func TestUpdateDirectory(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, DirectoryFullResponse{
				Name:    "updated-dir",
				UUIDURL: "dir-uuid-123",
			}),
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "update failed"),
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			resp, err := UpdateDirectory(context.Background(), ec, "dir-uuid-123", &DirectoryFullResponse{Name: "updated-dir"})
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "updated-dir", resp.Name)
		})
	}
}

func TestVerifyDirectory(t *testing.T) {
	tests := map[string]struct {
		setupRouter func(*pathRouter)
		wantErr     bool
	}{
		"success": {
			setupRouter: func(pr *pathRouter) {
				pr.Handle("POST", "/crux/v1/mgmt-pop/directories/dir-123/verify", jsonHandler(http.StatusOK, VerifyResponse{
					DirStatus: 5,
					CmdID:     "cmd-123",
					Status:    "pending",
				}))
				pr.Handle("GET", "/crux/v1/mgmt-pop/directories/dir-123/verify/cmd-123", jsonHandler(http.StatusOK, VerifyResponse{
					DirStatus: 7,
					Status:    "complete",
					CmdID:     "cmd-123",
				}))
			},
		},
		"verify_initiate_fails": {
			setupRouter: func(pr *pathRouter) {
				pr.Handle("POST", "/crux/v1/mgmt-pop/directories/dir-123/verify", errorJSONHandler(http.StatusInternalServerError, "verify failed"))
			},
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			pr := newPathRouter(t)
			tt.setupRouter(pr)
			ec := newTestClient(t, pr)
			err := VerifyDirectory(context.Background(), ec, "dir-123")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestSearchDirectoryGroup(t *testing.T) {
	tests := map[string]struct {
		setupRouter func(*pathRouter)
		wantName    string
		wantErr     bool
	}{
		"success": {
			setupRouter: func(pr *pathRouter) {
				pr.Handle("POST", "/crux/v1/mgmt-pop/directories/dir-123/search", jsonHandler(http.StatusOK, SearchResponse{
					CmdID:  "search-cmd-123",
					Status: "PENDING",
				}))
				dataJSON, _ := json.Marshal([]SearchGroupResult{{
					Name:       "testgroup",
					DN:         "CN=testgroup,DC=test,DC=com",
					ExternalID: "ext-123",
					Assigned:   false,
				}})
				pr.Handle("POST", "/crux/v1/mgmt-pop/directories/dir-123/status", jsonHandler(http.StatusOK, SearchStatusResponse{
					Status: "SUCCESS",
					Data:   dataJSON,
				}))
			},
			wantName: "testgroup",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			pr := newPathRouter(t)
			tt.setupRouter(pr)
			ec := newTestClient(t, pr)
			result, err := SearchDirectoryGroup(context.Background(), ec, "dir-123", "testgroup")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantName, result.Name)
		})
	}
}

func TestAssignDirectoryGroup(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, DirectoryGroupEntry{
				Name:    "testgroup",
				UUIDURL: "group-uuid-123",
			}),
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "assign failed"),
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			result, err := AssignDirectoryGroup(context.Background(), ec, "dir-123", &SearchGroupResult{
				Name:       "testgroup",
				DN:         "CN=testgroup,DC=test,DC=com",
				ExternalID: "ext-123",
			})
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "testgroup", result.Name)
		})
	}
}

func TestGetDirectoryGroups(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
		wantLen int
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, DirectoryGroupsResponse{
				Objects: []DirectoryGroupEntry{
					{Name: "group1", UUIDURL: "g1"},
					{Name: "group2", UUIDURL: "g2"},
				},
				Meta: Meta{TotalCount: 2},
			}),
			wantLen: 2,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			groups, err := GetDirectoryGroups(context.Background(), ec, "dir-123")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, groups, tt.wantLen)
		})
	}
}

func TestSyncDirectory(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, map[string]string{"message": "Syncing directories"}),
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "sync failed"),
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			err := SyncDirectory(context.Background(), ec, "dir-123")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestRemoveDirectoryGroup(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "remove failed"),
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			err := RemoveDirectoryGroup(context.Background(), ec, "dir-123", "group-uuid-456")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestDeleteDirectory(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success": {
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "delete failed"),
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			err := DeleteDirectory(context.Background(), ec, "dir-uuid-123")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
