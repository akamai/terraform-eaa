package eaaprovider

import (
	"context"
	"testing"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapBasicAttributesFromResponse(t *testing.T) {
	desc := "app description"
	host := "app.example.com"
	originHost := "origin.internal"
	cname := "app.cname.example.com"

	d := createTestApplicationResourceData(t, map[string]interface{}{
		"advanced_settings": map[string]interface{}{
			"app_auth": "saml",
		},
	})

	appResp := &client.ApplicationResponse{
		Name:           "test-app",
		Description:    &desc,
		Host:           &host,
		OriginHost:     &originHost,
		OrigTLS:        "strict",
		OriginPort:     443,
		CName:          &cname,
		AppProfile:     int(client.APP_PROFILE_HTTP),
		AppType:        int(client.APP_TYPE_ENTERPRISE_HOSTED),
		ClientAppMode:  int(client.CLIENT_APP_MODE_TCP),
		Domain:         int(client.APP_DOMAIN_WAPP),
		DomainSuffix:   ".example",
		POP:            "sea",
		POPName:        "Seattle",
		POPRegion:      "US",
		AuthEnabled:    "true",
		AppDeployed:    true,
		AppOperational: 1,
		AppStatus:      1,
		UUIDURL:        "app-uuid",
		AppCategory: client.AppCategory{
			Name: "business",
		},
	}

	ec := &client.EaaClient{}
	diags := mapBasicAttributesFromResponse(context.Background(), d, appResp, ec)
	require.False(t, diags.HasError())

	assert.Equal(t, "test-app", d.Get("name"))
	assert.Equal(t, desc, d.Get("description"))
	assert.Equal(t, "http", d.Get("app_profile"))
	assert.Equal(t, "enterprise", d.Get("app_type"))
	assert.Equal(t, "tcp", d.Get("client_app_mode"))
	assert.Equal(t, "wapp", d.Get("domain"))
	assert.Equal(t, ".example", d.Get("domain_suffix"))
	assert.Equal(t, host, d.Get("host"))
	assert.Equal(t, originHost, d.Get("origin_host"))
	assert.Equal(t, "strict", d.Get("orig_tls"))
	assert.Equal(t, 443, d.Get("origin_port"))
	assert.Equal(t, true, d.Get("saml"))
	assert.Equal(t, false, d.Get("oidc"))
	assert.Equal(t, false, d.Get("wsfed"))
	assert.Equal(t, "business", d.Get("app_category"))
	assert.Equal(t, "", d.Get("cert"))
	assert.Equal(t, "", d.Get("app_bundle"))
}

func TestMapServersAndTunnelHostsFromResponse(t *testing.T) {
	t.Run("enterprise_maps_servers_only", func(t *testing.T) {
		d := createTestApplicationResourceData(t, map[string]interface{}{})
		appResp := &client.ApplicationResponse{
			AppType: int(client.APP_TYPE_ENTERPRISE_HOSTED),
			Servers: []client.Server{
				{OriginHost: "srv1.internal", OrigTLS: true, OriginPort: 443, OriginProtocol: "https"},
				{OriginHost: "srv2.internal", OrigTLS: false, OriginPort: 80, OriginProtocol: "http"},
			},
		}

		diags := mapServersAndTunnelHostsFromResponse(d, appResp)
		require.False(t, diags.HasError())

		serversRaw := d.Get("servers").([]interface{})
		require.Len(t, serversRaw, 2)
		first := serversRaw[0].(map[string]interface{})
		assert.Equal(t, "srv1.internal", first["origin_host"])
		assert.Equal(t, true, first["orig_tls"])
		assert.Equal(t, 443, first["origin_port"])
		assert.Equal(t, "https", first["origin_protocol"])
	})

	t.Run("tunnel_maps_servers_and_tunnel_hosts", func(t *testing.T) {
		d := createTestApplicationResourceData(t, map[string]interface{}{})
		appResp := &client.ApplicationResponse{
			AppType: int(client.APP_TYPE_TUNNEL),
			Servers: []client.Server{{OriginHost: "srv.internal", OrigTLS: true, OriginPort: 443, OriginProtocol: "https"}},
			TunnelInternalHosts: []client.TunnelInternalHost{
				{Host: "10.0.0.1", PortRange: "22", ProtoType: 6},
			},
		}

		diags := mapServersAndTunnelHostsFromResponse(d, appResp)
		require.False(t, diags.HasError())

		tunnelRaw := d.Get("tunnel_internal_hosts").([]interface{})
		require.Len(t, tunnelRaw, 1)
		mapped := tunnelRaw[0].(map[string]interface{})
		assert.Equal(t, "10.0.0.1", mapped["host"])
		assert.Equal(t, "22", mapped["port_range"])
		assert.Equal(t, 6, mapped["proto_type"])
	})
}

func TestMapAgentsAndAuthFromResponse_CertBody(t *testing.T) {
	certUUID := "cert-uuid-123"
	pemBody := "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"

	appUUID := "test-app-uuid"
	svcUUID := "acl-svc-uuid"

	baseRoutes := func(mockTransport *MockHTTPTransport) {
		mockTransport.Responses["GET /crux/v1/mgmt-pop/apps/"+appUUID+"/agents"] = MockResponse{
			StatusCode: 200,
			Body:       client.AppAgentResponse{},
		}
		mockTransport.Responses["GET /crux/v1/mgmt-pop/apps/"+appUUID+"/services"] = MockResponse{
			StatusCode: 200,
			Body: client.AppServicesResponse{
				AppServices: []client.AppServiceData{{
					Service: client.AppService{
						UUIDURL:     svcUUID,
						ServiceType: int(client.SERVICE_TYPE_ACCESS_CTRL),
					},
				}},
			},
		}
		mockTransport.Responses["GET /crux/v1/mgmt-pop/services/"+svcUUID+"/rules"] = MockResponse{
			StatusCode: 200,
			Body:       client.ACLRulesResponse{},
		}
	}

	t.Run("cert_body_set_on_successful_fetch", func(t *testing.T) {
		mockClient, mockTransport := createMockClient(t)
		baseRoutes(mockTransport)
		mockTransport.Responses["GET /crux/v1/mgmt-pop/certificates/"+certUUID] = MockResponse{
			StatusCode: 200,
			Body: client.CertificateResponse{
				UUIDURL: certUUID,
				Cert:    pemBody,
			},
		}

		d := createTestApplicationResourceData(t, map[string]interface{}{})
		appResp := &client.ApplicationResponse{Cert: &certUUID, UUIDURL: appUUID}

		diags := mapAgentsAndAuthFromResponse(context.Background(), d, appResp, mockClient)
		require.False(t, diags.HasError())
		assert.Equal(t, pemBody, d.Get("cert_body"))
	})

	t.Run("cert_body_cleared_when_cert_is_nil", func(t *testing.T) {
		mockClient, mockTransport := createMockClient(t)
		baseRoutes(mockTransport)

		d := createTestApplicationResourceData(t, map[string]interface{}{})
		appResp := &client.ApplicationResponse{Cert: nil, UUIDURL: appUUID}

		diags := mapAgentsAndAuthFromResponse(context.Background(), d, appResp, mockClient)
		require.False(t, diags.HasError())
		assert.Equal(t, "", d.Get("cert_body"))
	})

	t.Run("cert_body_cleared_on_fetch_error", func(t *testing.T) {
		mockClient, mockTransport := createMockClient(t)
		baseRoutes(mockTransport)
		mockTransport.Responses["GET /crux/v1/mgmt-pop/certificates/"+certUUID] = MockResponse{
			StatusCode: 500,
			Body:       map[string]string{"detail": "internal error"},
		}

		d := createTestApplicationResourceData(t, map[string]interface{}{})
		appResp := &client.ApplicationResponse{Cert: &certUUID, UUIDURL: appUUID}

		diags := mapAgentsAndAuthFromResponse(context.Background(), d, appResp, mockClient)
		require.False(t, diags.HasError())
		assert.Equal(t, "", d.Get("cert_body"))
	})
}
