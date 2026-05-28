package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testPops = []Pop{
	{Region: "us-east-1", Name: "US East", UUIDURL: "pop-uuid-1", PopType: "shared"},
	{Region: "eu-west-1", Name: "EU West", UUIDURL: "pop-uuid-2", PopType: "shared"},
	{Region: "", Name: "", UUIDURL: ""}, // should be filtered out
}

func TestGetPops(t *testing.T) {
	tests := map[string]struct {
		handler   http.HandlerFunc
		wantCount int
		wantErr   bool
	}{
		"success": {
			handler:   jsonHandler(http.StatusOK, PopResponse{Pops: testPops}),
			wantCount: 2, // empty pop filtered out
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "server error"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)

			pops, err := GetPops(ec)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, pops, tt.wantCount)
		})
	}
}

func TestGetPopUUID(t *testing.T) {
	handler := jsonHandler(http.StatusOK, PopResponse{Pops: testPops})

	tests := map[string]struct {
		region   string
		wantName string
		wantUUID string
		wantErr  bool
	}{
		"found":     {region: "us-east-1", wantName: "US East", wantUUID: "pop-uuid-1"},
		"not_found": {region: "ap-south-1", wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, handler)

			gotName, gotUUID, err := GetPopUUID(ec, tt.region)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantName, gotName)
			assert.Equal(t, tt.wantUUID, gotUUID)
		})
	}
}
