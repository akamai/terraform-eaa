package client

import (
	"context"
	"encoding/json"
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
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
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
			requireErrIs(t, err, tt.wantErr, nil)
		})
	}
}

func TestRegistrationToken_Agents(t *testing.T) {
	body := `{
		"name": "tok",
		"agents": [
			{"uuid_url": "vLLqK77yT_Sx6Wa_vwnyjw", "name": "connector-a", "status": 1, "created_at": "2026-06-25T08:19:13.279315Z"},
			{"uuid_url": "otherUUID", "name": "connector-b", "status": 1, "created_at": "2026-06-25T08:19:13.279315Z"}
		]
	}`

	var token RegistrationToken
	require.NoError(t, json.Unmarshal([]byte(body), &token))

	assert.Equal(t, []RegistrationTokenAgent{
		{UUIDURL: "vLLqK77yT_Sx6Wa_vwnyjw", Name: "connector-a", Status: 1, CreatedAt: "2026-06-25T08:19:13.279315Z"},
		{UUIDURL: "otherUUID", Name: "connector-b", Status: 1, CreatedAt: "2026-06-25T08:19:13.279315Z"},
	}, token.Agents)
	assert.Equal(t, []string{"connector-a", "connector-b"}, token.AgentNames())
}

func TestRegistrationToken_AgentNames_Empty(t *testing.T) {
	var token RegistrationToken
	require.NoError(t, json.Unmarshal([]byte(`{"name":"tok","agents":[]}`), &token))
	assert.Equal(t, []string{}, token.AgentNames())
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

			got, err := ec.GetRegistrationTokens(context.Background(), "pool-1")
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
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

			got, err := ec.GetRegistrationTokenByUUID(context.Background(), tt.uuid, "pool-1")
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
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
			if requireErrIs(t, err, tt.wantErr, nil) {
				return
			}
		})
	}
}

func TestUpdateRegistrationToken(t *testing.T) {
	futureTime := time.Now().Add(24 * time.Hour).Format(time.RFC3339)

	tests := map[string]struct {
		req       *RegistrationTokenWriteRequest
		handler   http.HandlerFunc
		tokenUUID string
		wantErr   bool
	}{
		"success": {
			tokenUUID: "token-uuid-123",
			req: &RegistrationTokenWriteRequest{
				Name:      "updated-token",
				ExpiresAt: futureTime,
				MaxUse:    10,
			},
			handler: jsonHandler(200, nil),
		},
		"empty_uuid": {
			tokenUUID: "",
			req: &RegistrationTokenWriteRequest{
				Name:      "token",
				ExpiresAt: futureTime,
				MaxUse:    10,
			},
			wantErr: true,
		},
		"validation_failure_empty_name": {
			tokenUUID: "token-uuid-123",
			req: &RegistrationTokenWriteRequest{
				Name:      "",
				ExpiresAt: futureTime,
				MaxUse:    10,
			},
			wantErr: true,
		},
		"api_error": {
			tokenUUID: "token-uuid-123",
			req: &RegistrationTokenWriteRequest{
				Name:      "token",
				ExpiresAt: futureTime,
				MaxUse:    10,
			},
			handler: errorJSONHandler(500, "update failed"),
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var ec *EaaClient
			if tc.handler != nil {
				router := newPathRouter(t)
				router.Handle("PUT", "/crux/v1/zt/registration-token/"+tc.tokenUUID, tc.handler)
				ec = newTestClient(t, router)
			} else {
				ec = newTestClient(t, http.NotFoundHandler())
			}

			err := UpdateRegistrationToken(context.Background(), ec, tc.tokenUUID, tc.req)
			if requireErrIs(t, err, tc.wantErr, nil) {
				return
			}
		})
	}
}
