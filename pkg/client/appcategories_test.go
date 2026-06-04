package client

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testCategories() []AppCate {
	return []AppCate{
		{Name: "Web Apps", UUIDURL: "cat-uuid-1"},
		{Name: "SSH Apps", UUIDURL: "cat-uuid-2"},
		{Name: "", UUIDURL: ""}, // filtered
	}
}

func TestGetAppCategories(t *testing.T) {
	tests := map[string]struct {
		handler   http.HandlerFunc
		wantCount int
		wantErr   bool
	}{
		"success": {
			handler:   jsonHandler(http.StatusOK, AppCategoryResponse{AppCategories: testCategories()}),
			wantCount: 2,
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "error"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)

			cats, err := GetAppCategories(ec)
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
			assert.Len(t, cats, tt.wantCount)
		})
	}
}

func TestGetAppCategoryUUID(t *testing.T) {
	handler := jsonHandler(http.StatusOK, AppCategoryResponse{AppCategories: testCategories()})

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
			ec := newTestClient(t, handler)

			got, err := GetAppCategoryUUID(ec, tt.name)
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
			assert.Equal(t, tt.wantUUID, got)
		})
	}
}
