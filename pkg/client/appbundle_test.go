package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newAppBundleTestClient(t *testing.T, handler http.HandlerFunc) (client *EaaClient, cleanup func()) {
	t.Helper()
	ts := httptest.NewTLSServer(handler)
	ec := &EaaClient{
		Signer: noopSigner{},
		Client: ts.Client(),
		Host:   ts.Listener.Addr().String(),
	}
	return ec, ts.Close
}

func serveAppBundles(bundles []AppBundle) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AppBundleResponse{Objects: bundles}) //nolint:errcheck // test helper; encoding error is not actionable
	}
}

var testBundles = []AppBundle{
	{Name: "bundle-a", UUIDURL: "/appbundle/uuid-a"},
	{Name: "bundle-b", UUIDURL: "/appbundle/uuid-b"},
}

func TestGetAppBundleByName(t *testing.T) {
	tests := map[string]struct {
		name          string
		wantUUID      string
		wantErrSubstr string
	}{
		"match_first": {
			name:     "bundle-a",
			wantUUID: "/appbundle/uuid-a",
		},
		"match_second": {
			name:     "bundle-b",
			wantUUID: "/appbundle/uuid-b",
		},
		"not_found": {
			name:          "bundle-c",
			wantErrSubstr: "not found",
		},
		"partial_name_no_exact_match": {
			name:          "bundle",
			wantErrSubstr: "not found",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec, cleanup := newAppBundleTestClient(t, serveAppBundles(testBundles))
			defer cleanup()

			got, err := ec.GetAppBundleByName(context.Background(), tt.name)
			if tt.wantErrSubstr != "" {
				if err == nil {
					t.Fatalf("GetAppBundleByName(%q) returned nil error, want error containing %q", tt.name, tt.wantErrSubstr)
				}
				if !strings.Contains(err.Error(), tt.wantErrSubstr) {
					t.Fatalf("GetAppBundleByName(%q) error = %q, want error containing %q", tt.name, err.Error(), tt.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetAppBundleByName(%q) returned unexpected error: %v", tt.name, err)
			}
			if got != tt.wantUUID {
				t.Fatalf("GetAppBundleByName(%q) = %q, want %q", tt.name, got, tt.wantUUID)
			}
		})
	}
}

func TestGetAppBundleNameByUUID(t *testing.T) {
	tests := map[string]struct {
		uuid          string
		wantName      string
		wantErrSubstr string
	}{
		"match_first": {
			uuid:     "/appbundle/uuid-a",
			wantName: "bundle-a",
		},
		"match_second": {
			uuid:     "/appbundle/uuid-b",
			wantName: "bundle-b",
		},
		"not_found": {
			uuid:          "/appbundle/uuid-c",
			wantErrSubstr: "not found",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec, cleanup := newAppBundleTestClient(t, serveAppBundles(testBundles))
			defer cleanup()

			got, err := ec.GetAppBundleNameByUUID(context.Background(), tt.uuid)
			if tt.wantErrSubstr != "" {
				if err == nil {
					t.Fatalf("GetAppBundleNameByUUID(%q) returned nil error, want error containing %q", tt.uuid, tt.wantErrSubstr)
				}
				if !strings.Contains(err.Error(), tt.wantErrSubstr) {
					t.Fatalf("GetAppBundleNameByUUID(%q) error = %q, want error containing %q", tt.uuid, err.Error(), tt.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetAppBundleNameByUUID(%q) returned unexpected error: %v", tt.uuid, err)
			}
			if got != tt.wantName {
				t.Fatalf("GetAppBundleNameByUUID(%q) = %q, want %q", tt.uuid, got, tt.wantName)
			}
		})
	}
}
