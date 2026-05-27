package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssignIDP(t *testing.T) {
	tests := map[string]struct {
		errIs   error
		handler http.HandlerFunc
		appIdp  AppIdp
		wantErr bool
	}{
		"success": {
			appIdp:  AppIdp{App: "app-uuid-1", IDP: "idp-uuid-1"},
			handler: jsonHandler(http.StatusOK, nil),
		},
		"empty_app": {
			appIdp:  AppIdp{App: "", IDP: "idp-uuid-1"},
			handler: jsonHandler(http.StatusOK, nil), // shouldn't be called
			wantErr: true,
			errIs:   ErrAssignIdpFailure,
		},
		"empty_idp": {
			appIdp:  AppIdp{App: "app-uuid-1", IDP: ""},
			handler: jsonHandler(http.StatusOK, nil),
			wantErr: true,
			errIs:   ErrAssignIdpFailure,
		},
		"both_empty": {
			appIdp:  AppIdp{App: "", IDP: ""},
			handler: jsonHandler(http.StatusOK, nil),
			wantErr: true,
			errIs:   ErrAssignIdpFailure,
		},
		"api_error": {
			appIdp:  AppIdp{App: "app-uuid-1", IDP: "idp-uuid-1"},
			handler: errorJSONHandler(http.StatusInternalServerError, "assign failed"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec, cleanup := newTestClient(t, tt.handler)
			defer cleanup()

			err := tt.appIdp.AssignIDP(ec)
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

func TestUnAssignIDP(t *testing.T) {
	tests := map[string]struct {
		errIs   error
		handler http.HandlerFunc
		appIdp  AppIdp
		wantErr bool
	}{
		"success": {
			appIdp:  AppIdp{App: "app-uuid-1", IDP: "idp-uuid-1"},
			handler: jsonHandler(http.StatusOK, nil),
		},
		"empty_app": {
			appIdp:  AppIdp{App: "", IDP: "idp-uuid-1"},
			handler: jsonHandler(http.StatusOK, nil),
			wantErr: true,
			errIs:   ErrAssignIdpFailure,
		},
		"empty_idp": {
			appIdp:  AppIdp{App: "app-uuid-1", IDP: ""},
			handler: jsonHandler(http.StatusOK, nil),
			wantErr: true,
			errIs:   ErrAssignIdpFailure,
		},
		"api_error": {
			appIdp:  AppIdp{App: "app-uuid-1", IDP: "idp-uuid-1"},
			handler: errorJSONHandler(http.StatusInternalServerError, "unassign failed"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec, cleanup := newTestClient(t, tt.handler)
			defer cleanup()

			err := tt.appIdp.UnAssignIDP(ec)
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
