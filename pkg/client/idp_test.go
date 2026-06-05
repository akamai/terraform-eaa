package client

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func idpRouter(t *testing.T) *pathRouter {
	router := newPathRouter(t)

	idpResp := IDPResponse{
		IDPS: []IDPResponseData{
			{Name: "idp-1", UUIDURL: "idp-uuid-1"},
			{Name: "idp-2", UUIDURL: "idp-uuid-2"},
		},
	}
	dirResp := DirectoryResponse{
		DirectoryList: []DirectoryData{
			{Name: "dir-1", UUID: "dir-uuid-1", Groups: []GroupData{{Name: "group-1", UUID_URL: "grp-uuid-1"}}},
		},
	}

	router.Handle(http.MethodGet, "/crux/v1/mgmt-pop/idp", jsonHandler(http.StatusOK, idpResp))
	router.Handle(http.MethodGet, "/crux/v1/mgmt-pop/idp/idp-uuid-1/directories", jsonHandler(http.StatusOK, dirResp))
	router.Handle(http.MethodGet, "/crux/v1/mgmt-pop/idp/idp-uuid-2/directories", jsonHandler(http.StatusOK, DirectoryResponse{}))
	return router
}

func TestGetIDPS(t *testing.T) {
	ec := newTestClient(t, idpRouter(t))

	idpList, err := GetIDPS(context.Background(), ec)
	require.NoError(t, err)
	assert.Len(t, idpList.IDPS, 2)
	assert.Equal(t, "idp-1", idpList.IDPS[0].Name)
}

func TestGetIdpWithName(t *testing.T) {
	tests := map[string]struct {
		name    string
		wantErr bool
	}{
		"found":     {name: "idp-1"},
		"not_found": {name: "idp-missing", wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, idpRouter(t))

			got, err := GetIdpWithName(context.Background(), ec, tt.name)
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
			assert.Equal(t, tt.name, got.Name)
		})
	}
}

func TestGetIDPDirectories(t *testing.T) {
	ec := newTestClient(t, idpRouter(t))

	dirs, err := GetIDPDirectories(context.Background(), ec, "idp-uuid-1")
	require.NoError(t, err)
	assert.Len(t, dirs, 1)
	assert.Equal(t, "dir-1", dirs[0].Name)
	assert.Len(t, dirs[0].Groups, 1)
}

func TestIDPData_GetIdpDirectory(t *testing.T) {
	idpData := &IDPData{
		Name:    "idp-1",
		UUIDURL: "idp-uuid-1",
		Directories: []DirectoryData{
			{Name: "dir-1", UUID: "dir-uuid-1"},
			{Name: "dir-2", UUID: "dir-uuid-2"},
		},
	}
	ec := newTestClient(t, jsonHandler(http.StatusOK, nil))

	tests := map[string]struct {
		dirName string
		wantErr bool
	}{
		"found":     {dirName: "dir-1"},
		"not_found": {dirName: "dir-missing", wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := idpData.GetIdpDirectory(context.Background(), ec, tt.dirName)
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
			assert.Equal(t, tt.dirName, got.Name)
		})
	}
}
