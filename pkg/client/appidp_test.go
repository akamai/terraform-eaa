package client

import (
	"net/http"
	"testing"
)

func TestAssignUnAssignIDP(t *testing.T) {
	type idpFunc func(*AppIdp, *EaaClient) error

	funcs := map[string]idpFunc{
		"AssignIDP":   (*AppIdp).AssignIDP,
		"UnAssignIDP": (*AppIdp).UnAssignIDP,
	}

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
		"both_empty": {
			appIdp:  AppIdp{App: "", IDP: ""},
			handler: jsonHandler(http.StatusOK, nil),
			wantErr: true,
			errIs:   ErrAssignIdpFailure,
		},
		"api_error": {
			appIdp:  AppIdp{App: "app-uuid-1", IDP: "idp-uuid-1"},
			handler: errorJSONHandler(http.StatusInternalServerError, "operation failed"),
			wantErr: true,
		},
	}

	for funcName, fn := range funcs {
		t.Run(funcName, func(t *testing.T) {
			for name, tt := range tests {
				t.Run(name, func(t *testing.T) {
					ec := newTestClient(t, tt.handler)

					appIdp := tt.appIdp // copy to avoid mutation
					err := fn(&appIdp, ec)
					if requireErrIs(t, err, tt.wantErr, tt.errIs) {
						return
					}
				})
			}
		})
	}
}
