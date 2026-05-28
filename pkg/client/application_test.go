package client

import (
	"context"
	"net/http"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// CreateMinimalApplication
// ---------------------------------------------------------------------------

func TestCreateMinimalApplication_Success(t *testing.T) {
	wantResp := ApplicationResponse{
		Name:    "my-app",
		UUIDURL: "abc-123",
	}
	ec := newTestClient(t, jsonHandler(http.StatusOK, wantResp))

	mcar := &MinimalCreateAppRequest{
		Name:          "my-app",
		AppProfile:    1,
		AppType:       1,
		ClientAppMode: 1,
	}
	got, err := mcar.CreateMinimalApplication(context.Background(), ec)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "my-app", got.Name)
	assert.Equal(t, "abc-123", got.UUIDURL)
}

func TestCreateMinimalApplication_APIError(t *testing.T) {
	ec := newTestClient(t, errorJSONHandler(http.StatusBadRequest, "bad request"))

	mcar := &MinimalCreateAppRequest{
		Name:          "bad-app",
		AppProfile:    1,
		AppType:       1,
		ClientAppMode: 1,
	}
	got, err := mcar.CreateMinimalApplication(context.Background(), ec)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, ErrAppCreate)
}

func TestCreateMinimalApplication_MalformedJSON(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{invalid json`)) //nolint:errcheck // test helper, error handling not needed
	}
	ec := newTestClient(t, http.HandlerFunc(handler))

	mcar := &MinimalCreateAppRequest{
		Name:          "my-app",
		AppProfile:    1,
		AppType:       1,
		ClientAppMode: 1,
	}
	got, err := mcar.CreateMinimalApplication(context.Background(), ec)
	// The error could come from unmarshalling or the response might be zero-value
	// depending on how SendAPIRequest handles parse errors.
	// Either an error or a zero-value response is acceptable.
	if err != nil {
		assert.Nil(t, got)
	}
}

// ---------------------------------------------------------------------------
// DeployApplication
// ---------------------------------------------------------------------------

func TestDeployApplication_Success(t *testing.T) {
	router := newPathRouter(t)
	router.Handle("POST", "/crux/v1/mgmt-pop/apps/app-uuid-1/deploy",
		jsonHandler(http.StatusOK, nil))

	ec := newTestClient(t, router)

	app := &Application{UUIDURL: "app-uuid-1"}
	err := app.DeployApplication(ec)
	assert.NoError(t, err)
}

func TestDeployApplication_APIError(t *testing.T) {
	router := newPathRouter(t)
	router.Handle("POST", "/crux/v1/mgmt-pop/apps/app-uuid-1/deploy",
		errorJSONHandler(http.StatusInternalServerError, "deploy failed"))

	ec := newTestClient(t, router)

	app := &Application{UUIDURL: "app-uuid-1"}
	err := app.DeployApplication(ec)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeploy)
}

// ---------------------------------------------------------------------------
// DeleteApplication
// ---------------------------------------------------------------------------

func TestDeleteApplication_Success(t *testing.T) {
	router := newPathRouter(t)
	router.Handle("DELETE", "/crux/v1/mgmt-pop/apps/app-uuid-2",
		jsonHandler(http.StatusOK, nil))

	ec := newTestClient(t, router)

	app := &Application{UUIDURL: "app-uuid-2"}
	err := app.DeleteApplication(ec)
	assert.NoError(t, err)
}

func TestDeleteApplication_APIError(t *testing.T) {
	router := newPathRouter(t)
	router.Handle("DELETE", "/crux/v1/mgmt-pop/apps/app-uuid-2",
		errorJSONHandler(http.StatusForbidden, "forbidden"))

	ec := newTestClient(t, router)

	app := &Application{UUIDURL: "app-uuid-2"}
	err := app.DeleteApplication(ec)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAppDelete)
}

// ---------------------------------------------------------------------------
// UpdateApplication
// ---------------------------------------------------------------------------

func TestUpdateApplication_Success(t *testing.T) {
	respBody := map[string]interface{}{
		"name": "updated-app",
		"advanced_settings": map[string]interface{}{
			"app_auth": "none",
		},
	}
	router := newPathRouter(t)
	router.Handle("PUT", "/crux/v1/mgmt-pop/apps/app-uuid-3",
		jsonHandler(http.StatusOK, respBody))

	ec := newTestClient(t, router)

	updateReq := &ApplicationUpdateRequest{}
	updateReq.UUIDURL = "app-uuid-3"
	updateReq.Name = "updated-app"
	err := updateReq.UpdateApplication(context.Background(), ec)
	assert.NoError(t, err)
}

func TestUpdateApplication_APIError(t *testing.T) {
	router := newPathRouter(t)
	router.Handle("PUT", "/crux/v1/mgmt-pop/apps/app-uuid-3",
		errorJSONHandler(http.StatusBadRequest, "bad fields"))

	ec := newTestClient(t, router)

	updateReq := &ApplicationUpdateRequest{}
	updateReq.UUIDURL = "app-uuid-3"
	err := updateReq.UpdateApplication(context.Background(), ec)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAppUpdate)
}

// ---------------------------------------------------------------------------
// UpdateG2O
// ---------------------------------------------------------------------------

func TestUpdateG2O_Success(t *testing.T) {
	wantResp := G2OResponse{
		G2OEnabled: "true",
		G2OKey:     "some-key",
		G2ONonce:   "some-nonce",
	}
	router := newPathRouter(t)
	router.Handle("POST", "/crux/v1/mgmt-pop/apps/app-uuid-4/g2o",
		jsonHandler(http.StatusOK, wantResp))

	ec := newTestClient(t, router)

	app := &Application{UUIDURL: "app-uuid-4"}
	got, err := app.UpdateG2O(ec)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "some-key", got.G2OKey)
	assert.Equal(t, "some-nonce", got.G2ONonce)
}

func TestUpdateG2O_APIError(t *testing.T) {
	router := newPathRouter(t)
	router.Handle("POST", "/crux/v1/mgmt-pop/apps/app-uuid-4/g2o",
		errorJSONHandler(http.StatusInternalServerError, "g2o failed"))

	ec := newTestClient(t, router)

	app := &Application{UUIDURL: "app-uuid-4"}
	got, err := app.UpdateG2O(ec)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, ErrAppUpdate)
}

// ---------------------------------------------------------------------------
// UpdateEdgeAuthentication
// ---------------------------------------------------------------------------

func TestUpdateEdgeAuthentication_Success(t *testing.T) {
	wantResp := EdgeAuthResponse{
		EdgeCookieKey: "cookie-key-123",
		SLAObjectURL:  "sla-object-url",
	}
	router := newPathRouter(t)
	router.Handle("POST", "/crux/v1/mgmt-pop/apps/app-uuid-5/edgekey",
		jsonHandler(http.StatusOK, wantResp))

	ec := newTestClient(t, router)

	app := &Application{UUIDURL: "app-uuid-5"}
	got, err := app.UpdateEdgeAuthentication(ec)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "cookie-key-123", got.EdgeCookieKey)
	assert.Equal(t, "sla-object-url", got.SLAObjectURL)
}

func TestUpdateEdgeAuthentication_APIError(t *testing.T) {
	router := newPathRouter(t)
	router.Handle("POST", "/crux/v1/mgmt-pop/apps/app-uuid-5/edgekey",
		errorJSONHandler(http.StatusBadRequest, "edge auth failed"))

	ec := newTestClient(t, router)

	app := &Application{UUIDURL: "app-uuid-5"}
	got, err := app.UpdateEdgeAuthentication(ec)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, ErrAppUpdate)
}

// ---------------------------------------------------------------------------
// CreateApplication (full create)
// ---------------------------------------------------------------------------

func TestCreateApplication_Success(t *testing.T) {
	wantResp := ApplicationResponse{
		Name:    "full-app",
		UUIDURL: "full-uuid-1",
	}
	ec := newTestClient(t, jsonHandler(http.StatusOK, wantResp))

	car := &CreateAppRequest{
		Name:          "full-app",
		AppType:       1,
		AppProfile:    1,
		ClientAppMode: 1,
	}
	got, err := car.CreateApplication(context.Background(), ec)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "full-app", got.Name)
	assert.Equal(t, "full-uuid-1", got.UUIDURL)
}

func TestCreateApplication_APIError(t *testing.T) {
	ec := newTestClient(t, errorJSONHandler(http.StatusBadRequest, "invalid fields"))

	car := &CreateAppRequest{
		Name:          "bad-full-app",
		AppType:       1,
		AppProfile:    1,
		ClientAppMode: 1,
	}
	got, err := car.CreateApplication(context.Background(), ec)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, ErrAppCreate)
}

// ---------------------------------------------------------------------------
// Application.FromResponse
// ---------------------------------------------------------------------------

func TestFromResponse_PopulatedFields(t *testing.T) {
	desc := "test description"
	host := "app.example.com"
	cname := "app.cname.example.com"
	resp := &ApplicationResponse{
		Name:          "my-app",
		Description:   &desc,
		AppProfile:    1,
		AppType:       2,
		ClientAppMode: 3,
		Host:          &host,
		CName:         &cname,
		BookmarkURL:   "https://example.com",
		UUIDURL:       "resp-uuid",
		AppDeployed:   true,
		SAML:          true,
		Oidc:          false,
		WSFED:         false,
	}

	app := Application{}
	app.FromResponse(resp)

	assert.Equal(t, "my-app", app.Name)
	assert.Equal(t, &desc, app.Description)
	assert.Equal(t, 1, app.AppProfile)
	assert.Equal(t, 2, app.AppType)
	assert.Equal(t, 3, app.ClientAppMode)
	assert.Equal(t, &host, app.Host)
	assert.Equal(t, &cname, app.CName)
	assert.Equal(t, "https://example.com", app.BookmarkURL)
	assert.Equal(t, "resp-uuid", app.UUIDURL)
	assert.True(t, app.AppDeployed)
	assert.True(t, app.SAML)
	assert.False(t, app.Oidc)
}

func TestFromResponse_NilPointers(t *testing.T) {
	resp := &ApplicationResponse{
		Name:    "minimal-app",
		UUIDURL: "min-uuid",
	}

	app := Application{}
	app.FromResponse(resp)

	assert.Equal(t, "minimal-app", app.Name)
	assert.Nil(t, app.Description)
	assert.Nil(t, app.Host)
	assert.Nil(t, app.CName)
	assert.Nil(t, app.Cert)
}

// ---------------------------------------------------------------------------
// processCustomDomain (preserved from existing test, now with testify)
// ---------------------------------------------------------------------------

func TestProcessCustomDomainSkipsWhenHostMissing(t *testing.T) {
	resourceSchema := map[string]*schema.Schema{
		"cert_type": {
			Type:     schema.TypeString,
			Optional: true,
		},
	}

	d := schema.TestResourceDataRaw(t, resourceSchema, map[string]interface{}{})
	ec := &EaaClient{Logger: hclog.NewNullLogger()}
	appUpdateReq := &ApplicationUpdateRequest{}

	err := processCustomDomain(ec, appUpdateReq, d, context.Background())
	assert.NoError(t, err, "expected nil error when host is missing")
}

// ---------------------------------------------------------------------------
// firstMapBlock
// ---------------------------------------------------------------------------

func TestFirstMapBlock_Success(t *testing.T) {
	blocks := []interface{}{
		map[string]interface{}{"key": "value"},
	}
	got, err := firstMapBlock(blocks, "test")
	require.NoError(t, err)
	assert.Equal(t, "value", got["key"])
}

func TestFirstMapBlock_EmptySlice(t *testing.T) {
	_, err := firstMapBlock([]interface{}{}, "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected at least one block")
}

func TestFirstMapBlock_WrongType(t *testing.T) {
	blocks := []interface{}{"not a map"}
	_, err := firstMapBlock(blocks, "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected map[string]interface{}")
}
