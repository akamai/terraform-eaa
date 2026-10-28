package eaaprovider

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// dataSourceApplication — schema validation
// ---------------------------------------------------------------------------

func TestDataSourceApplication_SchemaBasics(t *testing.T) {
	ds := dataSourceApplication()
	assertDataSourceBasics(t, ds, "name", schema.TypeString)
	assertDataSourceBasics(t, ds, "uuid_url", schema.TypeString)
}

func TestDataSourceApplication_LookupFields(t *testing.T) {
	ds := dataSourceApplication()
	for _, field := range []string{"name", "uuid_url"} {
		t.Run(field, func(t *testing.T) {
			f := ds.Schema[field]
			require.NotNil(t, f)
			assert.True(t, f.Optional, "must be optional")
			assert.True(t, f.Computed, "must be computed")
			assert.False(t, f.Required, "must not be required")
			assert.ElementsMatch(t, []string{"name", "uuid_url"}, f.ExactlyOneOf)
		})
	}
}

func TestDataSourceApplication_OtherFieldsComputedOnly(t *testing.T) {
	ds := dataSourceApplication()
	for key, f := range ds.Schema {
		if key == "name" || key == "uuid_url" {
			continue
		}
		t.Run(key, func(t *testing.T) {
			assert.True(t, f.Computed, "must be computed")
			assert.False(t, f.Optional, "must not be optional")
			assert.False(t, f.Required, "must not be required")
		})
	}
}

func TestDataSourceApplication_NoConfigurableConstraints(t *testing.T) {
	var walk func(path string, s map[string]*schema.Schema)
	walk = func(path string, s map[string]*schema.Schema) {
		for key, f := range s {
			p := path + key
			assert.Nil(t, f.ValidateFunc, "%s: ValidateFunc", p)
			assert.Nil(t, f.ValidateDiagFunc, "%s: ValidateDiagFunc", p)
			assert.Nil(t, f.Default, "%s: Default", p)
			assert.Nil(t, f.DiffSuppressFunc, "%s: DiffSuppressFunc", p)
			assert.Zero(t, f.MaxItems, "%s: MaxItems", p)
			assert.False(t, f.ForceNew, "%s: ForceNew", p)
			if elem, ok := f.Elem.(*schema.Resource); ok {
				walk(p+".", elem.SchemaMap())
			}
		}
	}
	walk("", dataSourceApplication().Schema)
}

func TestDataSourceApplication_CoversResourceSchema(t *testing.T) {
	ds := dataSourceApplication()
	for key := range resourceEaaApplication().Schema {
		assert.Contains(t, ds.Schema, key, "resource attribute %q missing in data source", key)
	}
}

func TestDataSourceApplication_InternalValidate(t *testing.T) {
	require.NoError(t, dataSourceApplication().InternalValidate(nil, false))
}

func TestDataSourceApplication_DoesNotMutateResourceSchema(t *testing.T) {
	_ = dataSourceApplication()
	rs := resourceEaaApplication().Schema
	assert.True(t, rs["name"].Required, "resource name must stay required")
	assert.False(t, rs["name"].Computed, "resource name must not become computed")

	// Find a field that has a validator and make sure it is still there.
	checked := false
	for key, f := range rs {
		if f.ValidateFunc != nil || f.ValidateDiagFunc != nil {
			assert.True(t, f.ValidateFunc != nil || f.ValidateDiagFunc != nil, "validator on %q lost", key)
			checked = true
			break
		}
	}
	assert.True(t, checked, "expected at least one resource field with a validator")
}

// ---------------------------------------------------------------------------
// dataSourceApplicationRead — behavioral tests
// ---------------------------------------------------------------------------

const (
	testDSAppID   = "ds-app-uuid-1"
	testDSAppID2  = "ds-app-uuid-2"
	testDSAppName = "ds-app"
)

// registerAppListMock registers the v3 apps list with the given (name, uuid_url) pairs.
func registerAppListMock(mt *MockHTTPTransport, apps ...[2]string) {
	objects := make([]map[string]interface{}, 0, len(apps))
	for _, a := range apps {
		objects = append(objects, map[string]interface{}{"name": a[0], "uuid_url": a[1]})
	}
	mt.Responses["GET /crux/v3/mgmt-pop/apps"] = MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"objects": objects,
			"meta": map[string]interface{}{
				"next":        nil,
				"limit":       100,
				"offset":      0,
				"total_count": len(objects),
			},
		},
	}
}

// registerAppReadMocks registers everything a full application read needs for appID.
// extra is merged into the application body.
func registerAppReadMocks(mt *MockHTTPTransport, appID, name string, extra map[string]interface{}) {
	body := map[string]interface{}{
		"uuid_url":    appID,
		"name":        name,
		"app_type":    1,
		"app_profile": 1,
		"host":        "ds.example.com",
		"description": "data source app",
	}
	for k, v := range extra {
		body[k] = v
	}
	mt.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s", appID)] = MockResponse{StatusCode: http.StatusOK, Body: body}
	mt.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s/services", appID)] = MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"objects": []map[string]interface{}{
				{
					"service":  map[string]interface{}{"service_type": 6, "uuid_url": "service-uuid-" + appID},
					"status":   1,
					"uuid_url": "service-data-uuid-" + appID,
				},
			},
		},
	}
	mt.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s/agents", appID)] = MockResponse{
		StatusCode: http.StatusOK,
		Body:       map[string]interface{}{"objects": []map[string]interface{}{}},
	}
	mt.Responses[fmt.Sprintf("GET /crux/v1/mgmt-pop/services/service-uuid-%s/rules", appID)] = MockResponse{
		StatusCode: http.StatusOK,
		Body:       map[string]interface{}{"objects": []map[string]interface{}{}},
	}
}

func TestDataSourceApplicationRead_ByUUIDURL(t *testing.T) {
	mockClient, mt := createMockClient(t)
	registerAppReadMocks(mt, testDSAppID, testDSAppName, nil)

	d := createTestResourceDataFor(t, dataSourceApplication, map[string]any{"uuid_url": testDSAppID})
	diags := dataSourceApplicationRead(context.Background(), d, mockClient)

	require.Empty(t, diags)
	assert.Equal(t, testDSAppID, d.Id())
	assert.Equal(t, testDSAppName, d.Get("name"))
	assert.Equal(t, "ds.example.com", d.Get("host"))
	assert.Equal(t, "data source app", d.Get("description"))
	assert.Zero(t, mt.Calls["GET /crux/v3/mgmt-pop/apps"], "list API must not be called when uuid_url is given")
}

func TestDataSourceApplicationRead_ByName(t *testing.T) {
	mockClient, mt := createMockClient(t)
	registerAppListMock(mt, [2]string{"other-app", testDSAppID2}, [2]string{testDSAppName, testDSAppID})
	registerAppReadMocks(mt, testDSAppID, testDSAppName, nil)

	d := createTestResourceDataFor(t, dataSourceApplication, map[string]any{"name": testDSAppName})
	diags := dataSourceApplicationRead(context.Background(), d, mockClient)

	require.Empty(t, diags)
	assert.Equal(t, testDSAppID, d.Id())
	assert.Equal(t, testDSAppName, d.Get("name"))
	assert.Equal(t, "ds.example.com", d.Get("host"))
	assert.Equal(t, 1, mt.Calls["GET /crux/v1/mgmt-pop/apps/"+testDSAppID], "only the matching app is fetched")
}

func TestDataSourceApplicationRead_NameNotFound(t *testing.T) {
	mockClient, mt := createMockClient(t)
	registerAppListMock(mt, [2]string{"other-app", testDSAppID2})

	d := createTestResourceDataFor(t, dataSourceApplication, map[string]any{"name": "missing"})
	diags := dataSourceApplicationRead(context.Background(), d, mockClient)

	require.True(t, diags.HasError(), "expected error diagnostics")
	assert.Empty(t, d.Id())

	uuid, err := resolveAppUUIDByName(context.Background(), mockClient, "missing")
	require.ErrorIs(t, err, ErrAppNotFound)
	assert.Empty(t, uuid)
	assert.Contains(t, err.Error(), "missing")
}

func TestResolveAppUUIDByName_Ambiguous(t *testing.T) {
	mockClient, mt := createMockClient(t)
	registerAppListMock(mt, [2]string{testDSAppName, testDSAppID}, [2]string{testDSAppName, testDSAppID2})

	uuid, err := resolveAppUUIDByName(context.Background(), mockClient, testDSAppName)
	require.ErrorIs(t, err, ErrAppNameAmbiguous)
	assert.Empty(t, uuid)
	assert.Contains(t, err.Error(), testDSAppID)
	assert.Contains(t, err.Error(), testDSAppID2)

	d := createTestResourceDataFor(t, dataSourceApplication, map[string]any{"name": testDSAppName})
	diags := dataSourceApplicationRead(context.Background(), d, mockClient)
	require.True(t, diags.HasError(), "expected error diagnostics")
	assert.Empty(t, d.Id())
}

func TestResolveAppUUIDByName_Success(t *testing.T) {
	mockClient, mt := createMockClient(t)
	registerAppListMock(mt, [2]string{"other-app", testDSAppID2}, [2]string{testDSAppName, testDSAppID})

	uuid, err := resolveAppUUIDByName(context.Background(), mockClient, testDSAppName)
	require.NoError(t, err)
	assert.Equal(t, testDSAppID, uuid)
}

func TestDataSourceApplicationRead_AppNotFound(t *testing.T) {
	mockClient, mt := createMockClient(t)
	mt.Responses["GET /crux/v1/mgmt-pop/apps/"+testDSAppID] = MockResponse{
		StatusCode: http.StatusNotFound,
		Body: map[string]interface{}{
			"type":   "error",
			"title":  "Not Found",
			"detail": "Application not found",
		},
	}

	d := createTestResourceDataFor(t, dataSourceApplication, map[string]any{"uuid_url": testDSAppID})
	diags := dataSourceApplicationRead(context.Background(), d, mockClient)

	require.True(t, diags.HasError(), "expected error diagnostics for 404")
	assert.Empty(t, d.Id())
}

func TestDataSourceApplicationRead_ServerComputedAdvancedSettings(t *testing.T) {
	mockClient, mt := createMockClient(t)
	registerAppReadMocks(mt, testDSAppID, testDSAppName, map[string]interface{}{
		"advanced_settings": map[string]interface{}{
			"g2o_key":           "g2o-secret",
			"edge_cookie_key":   "cookie-secret",
			"websocket_enabled": "true",
		},
	})

	d := createTestResourceDataFor(t, dataSourceApplication, map[string]any{"uuid_url": testDSAppID})
	diags := dataSourceApplicationRead(context.Background(), d, mockClient)

	require.Empty(t, diags)
	adv, ok := d.Get("advanced_settings").(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "g2o-secret", adv["g2o_key"])
	assert.Equal(t, "cookie-secret", adv["edge_cookie_key"])
	assert.Equal(t, "true", adv["websocket_enabled"])
}

func TestDataSourceApplicationRead_ListAPIError(t *testing.T) {
	mockClient, mt := createMockClient(t)
	mt.Responses["GET /crux/v3/mgmt-pop/apps"] = MockResponse{
		StatusCode: http.StatusInternalServerError,
		Body: map[string]interface{}{
			"type":   "error",
			"title":  "Internal Server Error",
			"detail": "something went wrong",
		},
	}

	d := createTestResourceDataFor(t, dataSourceApplication, map[string]any{"name": testDSAppName})
	diags := dataSourceApplicationRead(context.Background(), d, mockClient)

	require.True(t, diags.HasError(), "expected error diagnostics for 500")
	assert.Empty(t, d.Id())

	_, err := resolveAppUUIDByName(context.Background(), mockClient, testDSAppName)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrAppNotFound)
}
