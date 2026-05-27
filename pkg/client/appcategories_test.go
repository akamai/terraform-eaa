package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testCategories = []AppCate{
	{Name: "Web Apps", UUIDURL: "cat-uuid-1"},
	{Name: "SSH Apps", UUIDURL: "cat-uuid-2"},
	{Name: "", UUIDURL: ""}, // filtered
}

func TestGetAppCategories(t *testing.T) {
	tests := map[string]struct {
		handler   http.HandlerFunc
		wantCount int
		wantErr   bool
	}{
		"success": {
			handler:   jsonHandler(http.StatusOK, AppCategoryResponse{AppCategories: testCategories}),
			wantCount: 2,
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "error"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec, cleanup := newTestClient(t, tt.handler)
			defer cleanup()

			cats, err := GetAppCategories(ec)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, cats, tt.wantCount)
		})
	}
}

func TestGetAppCategoryUUID(t *testing.T) {
	handler := jsonHandler(http.StatusOK, AppCategoryResponse{AppCategories: testCategories})

	tests := map[string]struct {
		name     string
		wantUUID string
		wantErr  bool
	}{
		"found":     {name: "Web Apps", wantUUID: "cat-uuid-1"},
		"not_found": {name: "Missing", wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec, cleanup := newTestClient(t, handler)
			defer cleanup()

			got, err := GetAppCategoryUUID(ec, tt.name)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantUUID, got)
		})
	}
}
