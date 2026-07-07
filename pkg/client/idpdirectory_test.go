package client

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetIDPDirectoryMemberships(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
		wantLen int
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, IDPDirectoryMembershipResponse{
				Objects: []IDPDirectoryMembership{
					{
						UUIDURL: "membership-1",
						Directory: IDPDirRef{
							UUIDURL: "dir-1",
							Name:    "Cloud Directory",
						},
						IDP: IDPRef{
							UUIDURL: "idp-1",
							Name:    "test-idp",
						},
					},
				},
			}),
			wantLen: 1,
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "error"),
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			memberships, err := GetIDPDirectoryMemberships(context.Background(), ec, "idp-1")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, memberships, tt.wantLen)
		})
	}
}

func TestAssociateDirectoriesToIDP(t *testing.T) {
	tests := map[string]struct {
		handler  http.HandlerFunc
		dirUUIDs []string
		wantErr  bool
	}{
		"success": {
			handler:  jsonHandler(http.StatusOK, []map[string]string{{"uuid_url": "membership-1"}}),
			dirUUIDs: []string{"dir-1", "dir-2"},
		},
		"empty_dirs": {
			handler:  jsonHandler(http.StatusOK, nil),
			dirUUIDs: []string{},
		},
		"api_error": {
			handler:  errorJSONHandler(http.StatusInternalServerError, "error"),
			dirUUIDs: []string{"dir-1"},
			wantErr:  true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			err := AssociateDirectoriesToIDP(context.Background(), ec, "idp-1", tt.dirUUIDs)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestDisassociateDirectoriesFromIDP(t *testing.T) {
	tests := map[string]struct {
		handler         http.HandlerFunc
		membershipUUIDs []string
		wantErr         bool
	}{
		"success": {
			handler:         jsonHandler(http.StatusOK, map[string]string{"message": "Successful"}),
			membershipUUIDs: []string{"membership-1"},
		},
		"empty_memberships": {
			handler:         jsonHandler(http.StatusOK, nil),
			membershipUUIDs: []string{},
		},
		"api_error": {
			handler:         errorJSONHandler(http.StatusInternalServerError, "error"),
			membershipUUIDs: []string{"membership-1"},
			wantErr:         true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)
			err := DisassociateDirectoriesFromIDP(context.Background(), ec, tt.membershipUUIDs)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
