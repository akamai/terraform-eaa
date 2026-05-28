// pkg/client/registrationtoken_test.go
package client

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatExpiresAt(t *testing.T) {
	tests := map[string]struct {
		input   string
		want    string
		wantErr bool
	}{
		"utc_timestamp": {
			input: "2026-06-15T14:30:01Z",
			want:  "2026-06-15T14:30:01Z",
		},
		"zero_seconds_bumped": {
			input: "2026-06-15T14:30:00Z",
			want:  "2026-06-15T14:30:01Z",
		},
		"with_offset": {
			input: "2026-06-15T10:30:01-04:00",
			want:  "2026-06-15T14:30:01Z",
		},
		"with_fractional_seconds": {
			input: "2026-06-15T14:30:01.123456Z",
			want:  "2026-06-15T14:30:01Z",
		},
		"invalid_format": {
			input:   "not-a-date",
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := FormatExpiresAt(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRegistrationTokenWriteRequest_Validate(t *testing.T) {
	futureTime := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	pastTime := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)

	tests := map[string]struct {
		req     RegistrationTokenWriteRequest
		wantErr bool
	}{
		"valid": {
			req: RegistrationTokenWriteRequest{
				Name:      "test-token",
				ExpiresAt: futureTime,
				MaxUse:    5,
			},
		},
		"empty_name": {
			req: RegistrationTokenWriteRequest{
				Name:      "",
				ExpiresAt: futureTime,
				MaxUse:    5,
			},
			wantErr: true,
		},
		"empty_expires_at": {
			req: RegistrationTokenWriteRequest{
				Name:   "test-token",
				MaxUse: 5,
			},
			wantErr: true,
		},
		"past_expires_at": {
			req: RegistrationTokenWriteRequest{
				Name:      "test-token",
				ExpiresAt: pastTime,
				MaxUse:    5,
			},
			wantErr: true,
		},
		"max_use_too_low": {
			req: RegistrationTokenWriteRequest{
				Name:      "test-token",
				ExpiresAt: futureTime,
				MaxUse:    0,
			},
			wantErr: true,
		},
		"max_use_too_high": {
			req: RegistrationTokenWriteRequest{
				Name:      "test-token",
				ExpiresAt: futureTime,
				MaxUse:    1001,
			},
			wantErr: true,
		},
		"invalid_timestamp_format": {
			req: RegistrationTokenWriteRequest{
				Name:      "test-token",
				ExpiresAt: "not-a-date",
				MaxUse:    5,
			},
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetRegistrationTokens(t *testing.T) {
	tokens := []RegistrationToken{
		{Name: "token-1", UUIDURL: "tok-uuid-1", ConnectorPool: "pool-1"},
		{Name: "token-2", UUIDURL: "tok-uuid-2", ConnectorPool: "pool-1"},
	}
	resp := RegistrationTokenResponse{Objects: tokens}

	tests := map[string]struct {
		handler http.HandlerFunc
		wantLen int
		wantErr bool
	}{
		"success": {
			handler: jsonHandler(http.StatusOK, resp),
			wantLen: 2,
		},
		"api_error": {
			handler: errorJSONHandler(http.StatusInternalServerError, "error"),
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)

			got, err := ec.GetRegistrationTokens("pool-1")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, got, tt.wantLen)
		})
	}
}

func TestGetRegistrationTokenByUUID(t *testing.T) {
	tokens := []RegistrationToken{
		{Name: "token-1", UUIDURL: "tok-uuid-1", ConnectorPool: "pool-1"},
		{Name: "token-2", UUIDURL: "tok-uuid-2", ConnectorPool: "pool-1"},
	}
	resp := RegistrationTokenResponse{Objects: tokens}
	handler := jsonHandler(http.StatusOK, resp)

	tests := map[string]struct {
		uuid    string
		wantErr bool
	}{
		"found":     {uuid: "tok-uuid-1"},
		"not_found": {uuid: "tok-uuid-missing", wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, handler)

			got, err := ec.GetRegistrationTokenByUUID(tt.uuid, "pool-1")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.uuid, got.UUIDURL)
		})
	}
}

func TestDeleteRegistrationTokenByUUID(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		wantErr bool
	}{
		"success_204": {handler: jsonHandler(http.StatusNoContent, nil)},
		"success_200": {handler: jsonHandler(http.StatusOK, nil)},
		"api_error":   {handler: errorJSONHandler(http.StatusNotFound, "not found"), wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)

			err := DeleteRegistrationTokenByUUID(context.Background(), ec, "tok-uuid-1")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestUpdateRegistrationToken(t *testing.T) {
	futureTime := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)

	tests := map[string]struct {
		req       *RegistrationTokenWriteRequest
		handler   http.HandlerFunc
		tokenUUID string
		wantErr   bool
	}{
		"success": {
			tokenUUID: "tok-uuid-1",
			req: &RegistrationTokenWriteRequest{
				Name:      "updated-token",
				ExpiresAt: futureTime,
				MaxUse:    10,
			},
			handler: jsonHandler(http.StatusOK, nil),
		},
		"empty_uuid": {
			tokenUUID: "",
			req: &RegistrationTokenWriteRequest{
				Name:      "test",
				ExpiresAt: futureTime,
				MaxUse:    1,
			},
			handler: jsonHandler(http.StatusOK, nil),
			wantErr: true,
		},
		"invalid_request": {
			tokenUUID: "tok-uuid-1",
			req:       &RegistrationTokenWriteRequest{Name: ""},
			handler:   jsonHandler(http.StatusOK, nil),
			wantErr:   true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := newTestClient(t, tt.handler)

			err := UpdateRegistrationToken(context.Background(), ec, tt.tokenUUID, tt.req)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
