package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAppIdpMembership(t *testing.T) {
	tests := map[string]struct {
		handler    http.HandlerFunc
		wantIDPURL string
		wantNil    bool
		wantErr    bool
	}{
		"success_with_membership": {
			handler: jsonHandler(http.StatusOK, AppIdpMembershipResponse{
				AppIdpMemberships: []AppIdpMembership{
					{
						IDP:     IDPMembership{IDPUUIDURL: "idp-uuid-1", Name: "my-idp"},
						App:     AppMembership{AppUUIDURL: "app-uuid-1", Name: "my-app"},
						UUIDURL: "membership-uuid-1",
					},
				},
			}),
			wantIDPURL: "idp-uuid-1",
		},
		"empty_memberships": {
			handler: jsonHandler(http.StatusOK, AppIdpMembershipResponse{
				AppIdpMemberships: []AppIdpMembership{},
			}),
			wantNil: true,
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "error"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)

			app := &Application{UUIDURL: "app-uuid-1"}
			got, err := app.GetAppIdpMembership(ec)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.wantIDPURL, got.IDP.IDPUUIDURL)
		})
	}
}

func TestGetAppDirectoryMembership(t *testing.T) {
	tests := map[string]struct {
		handler   http.HandlerFunc
		wantCount int
		wantErr   bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, AppDirectoryMembershipResponse{
				AppDirectoryMemberships: []AppDirectoryMembership{
					{
						Directory: DirectoryMembership{DirectoryUUIDURL: "dir-uuid-1", Name: "dir-1"},
						App:       AppMembership{AppUUIDURL: "app-uuid-1", Name: "my-app"},
					},
					{
						Directory: DirectoryMembership{DirectoryUUIDURL: "dir-uuid-2", Name: "dir-2"},
						App:       AppMembership{AppUUIDURL: "app-uuid-1", Name: "my-app"},
					},
				},
			}),
			wantCount: 2,
		},
		"empty": {
			handler: jsonHandler(http.StatusOK, AppDirectoryMembershipResponse{
				AppDirectoryMemberships: []AppDirectoryMembership{},
			}),
			wantCount: 0,
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "error"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)

			app := &Application{UUIDURL: "app-uuid-1"}
			got, err := app.GetAppDirectoryMembership(ec)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, got, tt.wantCount)
		})
	}
}

func TestGetAppGroupMembership(t *testing.T) {
	tests := map[string]struct {
		handler   http.HandlerFunc
		wantCount int
		wantErr   bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, AppGroupMembershipResponse{
				AppGroupMemberships: []AppGroupMembership{
					{
						Group: GroupMembership{DirName: "dir-1", GroupName: "group-1", GroupUUIDURL: "grp-uuid-1"},
						App:   AppMembership{AppUUIDURL: "app-uuid-1", Name: "my-app"},
					},
				},
			}),
			wantCount: 1,
		},
		"empty": {
			handler: jsonHandler(http.StatusOK, AppGroupMembershipResponse{
				AppGroupMemberships: []AppGroupMembership{},
			}),
			wantCount: 0,
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "error"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)

			app := &Application{UUIDURL: "app-uuid-1"}
			got, err := app.GetAppGroupMembership(ec)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, got, tt.wantCount)
		})
	}
}

func TestCreateAppAuthenticationStruct(t *testing.T) {
	tests := map[string]struct {
		setupRouter func(pr *pathRouter)
		wantIDP     string
		wantDirCnt  int
		wantErr     bool
	}{
		"full_membership_with_dirs_and_groups": {
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/apps/app-uuid-1/idp_membership", jsonHandler(http.StatusOK, AppIdpMembershipResponse{
					AppIdpMemberships: []AppIdpMembership{
						{
							IDP: IDPMembership{IDPUUIDURL: "idp-uuid-1", Name: "my-idp"},
							App: AppMembership{AppUUIDURL: "app-uuid-1", Name: "my-app"},
						},
					},
				}))
				pr.Handle("GET", "/crux/v1/mgmt-pop/apps/app-uuid-1/directories_membership", jsonHandler(http.StatusOK, AppDirectoryMembershipResponse{
					AppDirectoryMemberships: []AppDirectoryMembership{
						{
							Directory: DirectoryMembership{DirectoryUUIDURL: "dir-uuid-1", Name: "dir-1"},
							App:       AppMembership{AppUUIDURL: "app-uuid-1", Name: "my-app"},
						},
					},
				}))
				pr.Handle("GET", "/crux/v1/mgmt-pop/apps/app-uuid-1/groups", jsonHandler(http.StatusOK, AppGroupMembershipResponse{
					AppGroupMemberships: []AppGroupMembership{
						{
							Group: GroupMembership{DirName: "dir-1", GroupName: "group-1", GroupUUIDURL: "grp-uuid-1"},
							App:   AppMembership{AppUUIDURL: "app-uuid-1", Name: "my-app"},
						},
					},
				}))
			},
			wantIDP:    "my-idp",
			wantDirCnt: 1,
		},
		"nil_idp_membership": {
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/apps/app-uuid-1/idp_membership", jsonHandler(http.StatusOK, AppIdpMembershipResponse{
					AppIdpMemberships: []AppIdpMembership{},
				}))
			},
			wantIDP:    "",
			wantDirCnt: 0,
		},
		"idp_membership_error": {
			setupRouter: func(pr *pathRouter) {
				pr.Handle("GET", "/crux/v1/mgmt-pop/apps/app-uuid-1/idp_membership", errorJSONHandler(http.StatusInternalServerError, "error"))
			},
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			pr := newPathRouter(t)
			tt.setupRouter(pr)
			ec := newTestClient(t, pr)

			app := &Application{UUIDURL: "app-uuid-1"}
			got, err := app.CreateAppAuthenticationStruct(ec)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, got, 1)

			authMap, ok := got[0].(map[string]interface{})
			require.True(t, ok)
			assert.Equal(t, tt.wantIDP, authMap["app_idp"])

			dirs, ok := authMap["app_directories"].([]map[string]interface{})
			if tt.wantDirCnt == 0 {
				// Could be empty slice of either type
				if ok {
					assert.Len(t, dirs, 0)
				}
			} else {
				require.True(t, ok)
				assert.Len(t, dirs, tt.wantDirCnt)
			}
		})
	}
}
