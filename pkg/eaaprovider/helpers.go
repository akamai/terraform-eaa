package eaaprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// MockHTTPTransport intercepts HTTP requests and returns mocked responses
// This prevents real API calls during unit tests
type MockHTTPTransport struct {
	sync.RWMutex
	Responses            map[string]MockResponse
	connectors           map[string]map[string]interface{}
	connectorPools       map[string]map[string]interface{} // Track all pools by name
	deletedConnectorPools map[string]bool                  // Track deletion state for each pool
	apps                 map[string]map[string]interface{} // Track all apps by UUID
	appAgents            map[string][]string               // Track agents per app (by agent name)
	appIDPs              map[string]string                // Track IDP per app (by IDP name)
	appDirectories       map[string]map[string][]string   // Track directories per app: appUUID -> directoryName -> []groupNames
	idps                 map[string]map[string]interface{} // Track IDPs by name
}

type MockResponse struct {
	StatusCode int
	Body       interface{}
	Header     http.Header
}

// createHTTPResponseFromMock creates an HTTP response from MockResponse
func (m *MockHTTPTransport) createHTTPResponseFromMock(req *http.Request, mockResp MockResponse) (*http.Response, error) {
	var bodyBytes []byte
	var err error
	
	if mockResp.Body != nil {
		bodyBytes, err = json.Marshal(mockResp.Body)
		if err != nil {
			bodyBytes = []byte("{}")
		}
	} else {
		bodyBytes = []byte("{}")
	}
	
	header := mockResp.Header
	if header == nil {
		header = make(http.Header)
	}
	
	return &http.Response{
		StatusCode: mockResp.StatusCode,
		Status:     http.StatusText(mockResp.StatusCode),
		Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
		Header:     header,
		Request:    req,
	}, nil
}

// Implement RoundTrip method for MockHTTPTransport to satisfy http.RoundTripper
func (m *MockHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// First, check if there's a custom response in the Responses map
	// This allows tests to override default behavior
	m.RLock()
	
	// Try exact URL match first
	url := req.URL.String()
	if resp, ok := m.Responses[url]; ok {
		m.RUnlock()
		return m.createHTTPResponseFromMock(req, resp)
	}
	
	// Try method + path pattern match (e.g., "GET /crux/v1/mgmt-pop/apps/{id}")
	methodPattern := fmt.Sprintf("%s %s", req.Method, req.URL.Path)
	if resp, ok := m.Responses[methodPattern]; ok {
		m.RUnlock()
		return m.createHTTPResponseFromMock(req, resp)
	}
	
	// Try path-only match
	if resp, ok := m.Responses[req.URL.Path]; ok {
		m.RUnlock()
		return m.createHTTPResponseFromMock(req, resp)
	}
	
	// Try substring match for URL patterns
	for pattern, resp := range m.Responses {
		if strings.Contains(url, pattern) || strings.Contains(methodPattern, pattern) {
			m.RUnlock()
			return m.createHTTPResponseFromMock(req, resp)
		}
	}
	m.RUnlock()
	
	// Handle registration token endpoints (both registration-token and registration_tokens)
	if strings.Contains(req.URL.Path, "registration-token") || strings.Contains(req.URL.Path, "registration_tokens") || strings.Contains(req.URL.Path, "registrationtokens") {
		var poolUUID string = "mock-pool-uuid-123"
		
		// Handle POST request to create a registration token
		if req.Method == http.MethodPost {
			m.Lock()
			defer m.Unlock()
			
			// Parse the request body to extract token details
			var tokenRequest map[string]interface{}
			if req.Body != nil {
				bodyBytes, _ := io.ReadAll(req.Body)
				json.Unmarshal(bodyBytes, &tokenRequest)
				// Extract pool UUID from parsed JSON
				if cp, ok := tokenRequest["connector_pool"].(string); ok {
					poolUUID = cp
				}
			}
			
			// Extract token name and other fields
			tokenName := "mock-token"
			if name, ok := tokenRequest["name"].(string); ok {
				tokenName = name
			}
			maxUse := 1
			if mu, ok := tokenRequest["max_use"].(float64); ok {
				maxUse = int(mu)
			}
			expiresAt := "2099-12-31T23:59:59Z"
			if ea, ok := tokenRequest["expires_at"].(string); ok {
				expiresAt = ea
			}
			generateEmbeddedImg := false
			if gei, ok := tokenRequest["generate_embedded_img"].(bool); ok {
				generateEmbeddedImg = gei
			}
			
			// Ensure connector pool entry exists (pools are stored by name, and uuid_url == name)
			if m.connectorPools == nil {
				m.connectorPools = make(map[string]map[string]interface{})
			}
			// poolUUID should match the pool name since uuid_url is set to poolName
			if _, ok := m.connectorPools[poolUUID]; !ok {
				m.connectorPools[poolUUID] = map[string]interface{}{
					"uuid_url":            poolUUID,
					"name":                poolUUID,
					"package_type":        1,
					"registration_tokens": []map[string]interface{}{},
				}
			}
			
			// Create the new token with a unique UUID
			tokenUUID := poolUUID + "-" + tokenName + "-uuid"
			newToken := map[string]interface{}{
				"uuid_url":             tokenUUID,
				"name":                 tokenName,
				"max_use":              maxUse,
				"connector_pool":       poolUUID,
				"expires_at":           expiresAt,
				"token":                "mock-token-" + tokenName,
				"used_count":           0,
				"token_suffix":         "123",
				"modified_at":          expiresAt,
				"generate_embedded_img": generateEmbeddedImg,
			}
			
			// Add token to pool's registration_tokens list
			pool := m.connectorPools[poolUUID]
			tokens, ok := pool["registration_tokens"].([]map[string]interface{})
			if !ok {
				tokens = []map[string]interface{}{}
			}
			// Check if token with same name already exists, if so replace it
			found := false
			for i, t := range tokens {
				if tName, ok := t["name"].(string); ok && tName == tokenName {
					tokens[i] = newToken
					found = true
					break
				}
			}
			if !found {
				tokens = append(tokens, newToken)
			}
			pool["registration_tokens"] = tokens
			if len(tokens) > 0 {
				pool["registration_token"] = tokens[0]["token"] // Set the first token as default
			}
			m.connectorPools[poolUUID] = pool
			
			// Return success response with the created token
			// This prevents the client from hanging when trying to fetch the token
			tokenResponseBytes, _ := json.Marshal(newToken)
			return &http.Response{
				StatusCode: http.StatusCreated,
				Body:       io.NopCloser(strings.NewReader(string(tokenResponseBytes))),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}
		
		// Handle GET request to fetch registration tokens
		// Extract pool UUID from query parameter
		if req.URL.RawQuery != "" {
			for _, q := range strings.Split(req.URL.RawQuery, "&") {
				if strings.HasPrefix(q, "connector_pool_id=") {
					poolUUID = strings.TrimPrefix(q, "connector_pool_id=")
				}
			}
		}
		if poolUUID == "" {
			poolUUID = "mock-pool-uuid-123"
		}
		// Ensure connector pool entry exists for this poolUUID
		m.Lock()
		if m.connectorPools == nil {
			m.connectorPools = make(map[string]map[string]interface{})
		}
		if _, ok := m.connectorPools[poolUUID]; !ok {
			// Build registration_tokens from testdata for comprehensive pool and others
			var registrationTokens []map[string]interface{}
			switch poolUUID {
			case "test-pool-comprehensive":
				registrationTokens = []map[string]interface{}{
					{
						"name":                 "token-1",
						"max_use":              5,
						"expires_in_days":      1,
						"generate_embedded_img": false,
						"token":                "mock-token-1",
						"connector_pool":       poolUUID,
					},
					{
						"name":                 "token-2",
						"max_use":              10,
						"expires_in_days":      2,
						"generate_embedded_img": true,
						"token":                "mock-token-2",
						"connector_pool":       poolUUID,
					},
				}
			case "test-pool-update-tokens":
				registrationTokens = []map[string]interface{}{
					{
						"name":                 "initial-token",
						"max_use":              1,
						"expires_in_days":      1,
						"generate_embedded_img": false,
						"token":                "mock-token-initial-token",
						"connector_pool":       poolUUID,
					},
				}
			default:
				registrationTokens = []map[string]interface{}{
					{
						"name":                 poolUUID + "-token",
						"max_use":              1,
						"expires_in_days":      1,
						"generate_embedded_img": false,
						"token":                "mock-token-" + poolUUID,
						"connector_pool":       poolUUID,
					},
				}
			}
			m.connectorPools[poolUUID] = map[string]interface{}{
				"uuid_url":            poolUUID,
				"name":                poolUUID,
				"package_type":        1,
				"description":         "Test connector pool created by registration_tokens mock",
				"cidrs":               []string{"10.0.0.0/8"},
				"registration_token":  registrationTokens[0]["token"],
				"registration_tokens": registrationTokens,
			}
		}
		m.Unlock()
		// Try to match the token value to the connector pool's registration_token
		var tokenValue string = "mock-token-123"
		m.RLock()
		if m.connectorPools != nil {
			if pool, ok := m.connectorPools[poolUUID]; ok {
				if t, ok := pool["registration_token"].(string); ok {
					tokenValue = t
				}
			}
		}
		m.RUnlock()
		// Instead of hardcoded objects, build objects from pool config if available
		m.RLock()
		var objects []map[string]interface{}
		if pool, ok := m.connectorPools[poolUUID]; ok {
			if tokens, ok := pool["registration_tokens"].([]map[string]interface{}); ok {
				for _, t := range tokens {
					// Use the token's uuid_url if available, otherwise generate one
					tokenName := "mock-token"
					if name, ok := t["name"].(string); ok && name != "" {
						tokenName = name
					}
					tokenUUID := poolUUID + "-" + tokenName + "-uuid"
					if uuid, ok := t["uuid_url"].(string); ok && uuid != "" {
						tokenUUID = uuid
					}
					obj := map[string]interface{}{
						"name":                 t["name"],
						"max_use":              t["max_use"],
						"connector_pool":       poolUUID,
						"expires_at":           t["expires_at"],
						"token":                t["token"],
						"uuid_url":             tokenUUID,
						"used_count":           0,
						"token_suffix":         "123",
						"modified_at":          t["modified_at"],
						"generate_embedded_img": t["generate_embedded_img"],
					}
					// Set expires_at and modified_at if not present
					if obj["expires_at"] == nil || obj["expires_at"] == "" {
						obj["expires_at"] = "2099-12-31T23:59:59Z"
					}
					if obj["modified_at"] == nil || obj["modified_at"] == "" {
						obj["modified_at"] = "2099-12-31T23:59:59Z"
					}
					objects = append(objects, obj)
				}
			}
		}
		m.RUnlock()
		if len(objects) == 0 {
			// fallback to default
			objects = []map[string]interface{}{
				{
					"name":                 "mock-token",
					"max_use":              1,
					"connector_pool":       poolUUID,
					"expires_at":           "2099-12-31T23:59:59Z",
					"token":                tokenValue,
					"uuid_url":             poolUUID,
					"used_count":           0,
					"token_suffix":         "123",
					"modified_at":          "2099-12-31T23:59:59Z",
					"generate_embedded_img": false,
				},
			}
		}
		// Ensure meta field has proper structure
		meta := map[string]interface{}{
			"total_count": len(objects),
			"offset":      0,
			"limit":       100,
		}
		resp := map[string]interface{}{
			"meta":    meta,
			"objects": objects,
		}
		respBytes, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBytes))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle connector pool agent association endpoints
	// PUT /crux/v1/zt/connector-pools/{poolUUID}/agents/associate
	if strings.Contains(req.URL.Path, "agents/associate") && req.Method == http.MethodPut {
		// Return success response
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(`{"status": "success"}`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle connector pool agent disassociation endpoints
	// PUT /crux/v1/zt/connector-pools/{poolUUID}/agents/disassociate
	if strings.Contains(req.URL.Path, "agents/disassociate") && req.Method == http.MethodPut {
		// Return success response
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(`{"status": "success"}`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle app connector pool association endpoints
	// PUT /crux/v1/mgmt-pop/apps/{appUUID}/connector-pools/associate
	if strings.Contains(req.URL.Path, "connector-pools/associate") && req.Method == http.MethodPut {
		// Return success response
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(`{"status": "success"}`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	if strings.Contains(req.URL.Path, "connector-pool") || strings.Contains(req.URL.Path, "connector-pools") {
		// Extract pool name from request body (POST/PUT/PATCH) or URL (GET/DELETE/subresource)
		var poolName string = "test-connector-pool"
		parts := strings.Split(req.URL.Path, "/")
		for _, p := range parts {
			if p != "" && p != "connector-pool" && p != "connector-pools" && p != "v1" && p != "registration_tokens" {
				poolName = p
			}
		}
		if req.Method == http.MethodPost {
			if req.Body != nil {
				bodyBytes, _ := io.ReadAll(req.Body)
				bodyStr := string(bodyBytes)
				if strings.Contains(bodyStr, "name") {
					parts := strings.Split(bodyStr, "\"")
					for i, p := range parts {
						if p == "name" && i+2 < len(parts) {
							poolName = parts[i+2]
							break
						}
					}
				}
			}
			m.Lock()
			if m.connectorPools == nil {
				m.connectorPools = make(map[string]map[string]interface{})
			}
			// Set uuid_url to poolName for deterministic matching
			m.connectorPools[poolName] = map[string]interface{}{
				"uuid_url":      poolName,
				"name":          poolName,
				"package_type":  1,
				"infra_type":    1, // Required field: 1 = eaa
				"operating_mode": 1, // Required field: 1 = connector
				"description":   "Test connector pool created by unit tests",
				"cidrs":         []string{"10.0.0.0/8"},
			}
			if m.deletedConnectorPools == nil {
				m.deletedConnectorPools = make(map[string]bool)
			}
			m.deletedConnectorPools[poolName] = false
			m.connectorPools[poolName]["registration_token"] = "mock-token-123"
			m.connectorPools[poolName]["registration_tokens"] = []map[string]interface{}{{"token": "mock-token-123", "connector_pool": m.connectorPools[poolName]["uuid_url"]}}
			respBytes, _ := json.Marshal(m.connectorPools[poolName])
			m.Unlock()
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(string(respBytes))),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}
		if req.Method == http.MethodPut || req.Method == http.MethodPatch {
			// Handle update: ensure registration_token is always present
			if req.Body != nil {
				bodyBytes, _ := io.ReadAll(req.Body)
				bodyStr := string(bodyBytes)
				if strings.Contains(bodyStr, "name") {
					parts := strings.Split(bodyStr, "\"")
					for i, p := range parts {
						if p == "name" && i+2 < len(parts) {
							poolName = parts[i+2]
							break
						}
					}
				}
			}
			m.Lock()
			if m.connectorPools == nil {
				m.connectorPools = make(map[string]map[string]interface{})
			}
			pool, ok := m.connectorPools[poolName]
			if !ok {
				pool = map[string]interface{}{
					"uuid_url":     poolName,
					"name":         poolName,
					"package_type": 1,
					"description":  "Test connector pool created by unit tests",
					"cidrs":        []string{"10.0.0.0/8"},
				}
			}
			// Always set registration_token and registration_tokens
			pool["registration_token"] = "mock-token-123"
			pool["registration_tokens"] = []map[string]interface{}{{"token": "mock-token-123", "connector_pool": pool["uuid_url"]}}
			m.connectorPools[poolName] = pool
			if m.deletedConnectorPools == nil {
				m.deletedConnectorPools = make(map[string]bool)
			}
			m.deletedConnectorPools[poolName] = false
			respBytes, _ := json.Marshal(pool)
			m.Unlock()
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(string(respBytes))),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}
		if req.Method == http.MethodGet {
			// Try to extract pool name from URL
			parts := strings.Split(req.URL.Path, "/")
			for _, p := range parts {
				if p != "" && p != "connector-pool" && p != "connector-pools" {
					poolName = p
				}
			}
			m.RLock()
			deleted := m.deletedConnectorPools != nil && m.deletedConnectorPools[poolName]
			m.RUnlock()
			if deleted {
				return &http.Response{
					StatusCode: 404,
					Body:       io.NopCloser(strings.NewReader(`{"error": "not found"}`)),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			}
			m.Lock()
			if m.connectorPools == nil {
				m.connectorPools = make(map[string]map[string]interface{})
			}
			pool, ok := m.connectorPools[poolName]
			if !ok {
				pool = map[string]interface{}{
					"uuid_url":      poolName,
					"name":          poolName,
					"package_type":  1,
					"infra_type":    1, // Required field: 1 = eaa
					"operating_mode": 1, // Required field: 1 = connector
					"description":   "Test connector pool created by unit tests",
					"cidrs":         []string{"10.0.0.0/8"},
				}
			}
			// Ensure required fields are set
			if _, ok := pool["infra_type"]; !ok {
				pool["infra_type"] = 1
			}
			if _, ok := pool["operating_mode"]; !ok {
				pool["operating_mode"] = 1
			}
			// Always set registration_token and registration_tokens to match poolName
			pool["registration_token"] = "mock-token-" + poolName
			pool["registration_tokens"] = []map[string]interface{}{{"token": "mock-token-" + poolName, "connector_pool": poolName}}
			// Add applications field for GetAppsAssignedToPool
			// The client expects json.RawMessage, which should be a JSON array
			// We store it as a slice, and when marshaled it becomes a JSON array
			// The client will unmarshal it into json.RawMessage which is []byte
			applications := []map[string]interface{}{
				{"uuid_url": "app-uuid-test-app-01", "name": "test-app-01"},
			}
			// Store as slice directly - JSON marshal will encode it as an array
			pool["applications"] = applications
			// Add connectors field for GetConnectorsInPool
			connectors := []map[string]interface{}{
				{"uuid_url": "test-connector-01", "name": "test-connector-01"},
			}
			// Store as slice directly - JSON marshal will encode it as an array
			pool["connectors"] = connectors
			m.connectorPools[poolName] = pool
			m.Unlock()
			respBytes, _ := json.Marshal(pool)
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(string(respBytes))),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}
		if req.Method == http.MethodDelete {
			// Extract pool name from URL
			parts := strings.Split(req.URL.Path, "/")
			for _, p := range parts {
				if p != "" && p != "connector-pool" && p != "connector-pools" {
					poolName = p
				}
			}
			m.Lock()
			if m.deletedConnectorPools == nil {
				m.deletedConnectorPools = make(map[string]bool)
			}
			m.deletedConnectorPools[poolName] = true
			if m.connectorPools != nil {
				delete(m.connectorPools, poolName)
			}
			m.Unlock()
			return &http.Response{
				StatusCode: 204,
				Body:       io.NopCloser(strings.NewReader("{}")),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}
		// For other methods, return a 400 error to prevent hanging
		m.Lock()
		if m.connectorPools == nil {
			m.connectorPools = make(map[string]map[string]interface{})
		}
		pool, ok := m.connectorPools[poolName]
		if !ok {
			pool = map[string]interface{}{
				"uuid_url":      poolName,
				"name":          poolName,
				"package_type":  1,
				"infra_type":    1, // Required field: 1 = eaa
				"operating_mode": 1, // Required field: 1 = connector
				"description":   "Test connector pool created by unit tests",
				"cidrs":         []string{"10.0.0.0/8"},
			}
		}
		// Ensure required fields are set
		if _, ok := pool["infra_type"]; !ok {
			pool["infra_type"] = 1
		}
		if _, ok := pool["operating_mode"]; !ok {
			pool["operating_mode"] = 1
		}
		// Always set registration_token and registration_tokens
		pool["registration_token"] = "mock-token-123"
		pool["registration_tokens"] = []map[string]interface{}{{"token": "mock-token-123", "connector_pool": pool["uuid_url"]}}
		m.connectorPools[poolName] = pool
		respBytes, _ := json.Marshal(pool)
		m.Unlock()
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBytes))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle IDP directories endpoint - MUST come before idps check to avoid false matches
	// Path format: /crux/v1/mgmt-pop/idp/{idp-uuid}/directories
	if strings.Contains(req.URL.Path, "/directories") && (strings.Contains(req.URL.Path, "mgmt-pop/idp/") || strings.Contains(req.URL.Path, "/idp/")) {
		resp := map[string]interface{}{
			"meta":          map[string]interface{}{},
			"objects":       []map[string]interface{}{},
			"directory_list": []map[string]interface{}{}, // Also include directory_list for DirectoryResponse
		}
		respBytes, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBytes))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle singular idp endpoint (list all IDPs) - Path: /crux/v1/mgmt-pop/idp
	if req.URL.Path == "/crux/v1/mgmt-pop/idp" || (strings.Contains(req.URL.Path, "mgmt-pop/idp") && !strings.Contains(req.URL.Path, "idps") && !strings.Contains(req.URL.Path, "/directories")) {
		resp := map[string]interface{}{
			"meta": map[string]interface{}{},
			"objects": []map[string]interface{}{
				{"name": "Corporate AD", "uuid_url": "idp-uuid-1"},
				{"name": "External LDAP", "uuid_url": "idp-uuid-2"},
				{"name": "Test IDP", "uuid_url": "idp-uuid-3"},
				{"name": "OIDC IDP", "uuid_url": "idp-uuid-4"},
				{"name": "Kerberos IDP", "uuid_url": "idp-uuid-5"},
				{"name": "Basic Auth IDP", "uuid_url": "idp-uuid-6"},
				{"name": "JWT IDP", "uuid_url": "idp-uuid-7"},
				{"name": "WSFed IDP", "uuid_url": "idp-uuid-8"},
				{"name": "SAML IDP", "uuid_url": "idp-uuid-9"},
				{"name": "Tunnel IDP", "uuid_url": "idp-uuid-10"},
				{"name": "RDP IDP", "uuid_url": "idp-uuid-11"},
				{"name": "Bookmark IDP", "uuid_url": "idp-uuid-12"},
				{"name": "SaaS OIDC", "uuid_url": "idp-uuid-13"},
				{"name": "SaaS SAML", "uuid_url": "idp-uuid-14"},
				{"name": "SaaS WSFed", "uuid_url": "idp-uuid-15"},
				{"name": "Health Check IDP", "uuid_url": "idp-uuid-16"},
				{"name": "Load Balancer IDP", "uuid_url": "idp-uuid-17"},
				{"name": "Enterprise Connectivity IDP", "uuid_url": "idp-uuid-18"},
				{"name": "Import IDP", "uuid_url": "idp-uuid-19"},
				{"name": "test-idp", "uuid_url": "idp-uuid-20"},
			},
		}
		respBytes, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBytes))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Also respond to /mgmt-pop/idps and /zt/idps - check for exact list endpoints
	if (strings.Contains(req.URL.Path, "mgmt-pop/idps") || strings.Contains(req.URL.Path, "zt/idps")) && !strings.Contains(req.URL.Path, "/directories") {
		resp := map[string]interface{}{
			"meta": map[string]interface{}{},
			"objects": []map[string]interface{}{
				{"name": "Corporate AD", "uuid_url": "idp-uuid-1"},
				{"name": "External LDAP", "uuid_url": "idp-uuid-2"},
				{"name": "Test IDP", "uuid_url": "idp-uuid-3"},
				{"name": "OIDC IDP", "uuid_url": "idp-uuid-4"},
				{"name": "Kerberos IDP", "uuid_url": "idp-uuid-5"},
				{"name": "Basic Auth IDP", "uuid_url": "idp-uuid-6"},
				{"name": "JWT IDP", "uuid_url": "idp-uuid-7"},
				{"name": "WSFed IDP", "uuid_url": "idp-uuid-8"},
				{"name": "SAML IDP", "uuid_url": "idp-uuid-9"},
				{"name": "Tunnel IDP", "uuid_url": "idp-uuid-10"},
				{"name": "RDP IDP", "uuid_url": "idp-uuid-11"},
				{"name": "Bookmark IDP", "uuid_url": "idp-uuid-12"},
				{"name": "SaaS OIDC", "uuid_url": "idp-uuid-13"},
				{"name": "SaaS SAML", "uuid_url": "idp-uuid-14"},
				{"name": "SaaS WSFed", "uuid_url": "idp-uuid-15"},
				{"name": "Health Check IDP", "uuid_url": "idp-uuid-16"},
				{"name": "Load Balancer IDP", "uuid_url": "idp-uuid-17"},
				{"name": "Enterprise Connectivity IDP", "uuid_url": "idp-uuid-18"},
				{"name": "Import IDP", "uuid_url": "idp-uuid-19"},
				{"name": "test-idp", "uuid_url": "idp-uuid-20"},
			},
		}
		respBytes, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBytes))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle generic idps endpoint (fallback, but exclude directories)
	if strings.Contains(req.URL.Path, "idps") && !strings.Contains(req.URL.Path, "/directories") {
		resp := map[string]interface{}{
			"meta": map[string]interface{}{},
			"objects": []map[string]interface{}{
				{"name": "Corporate AD", "uuid_url": "idp-uuid-1"},
				{"name": "External LDAP", "uuid_url": "idp-uuid-2"},
				{"name": "Test IDP", "uuid_url": "idp-uuid-3"},
				{"name": "OIDC IDP", "uuid_url": "idp-uuid-4"},
				{"name": "Kerberos IDP", "uuid_url": "idp-uuid-5"},
				{"name": "Basic Auth IDP", "uuid_url": "idp-uuid-6"},
				{"name": "JWT IDP", "uuid_url": "idp-uuid-7"},
				{"name": "WSFed IDP", "uuid_url": "idp-uuid-8"},
				{"name": "SAML IDP", "uuid_url": "idp-uuid-9"},
				{"name": "Tunnel IDP", "uuid_url": "idp-uuid-10"},
				{"name": "RDP IDP", "uuid_url": "idp-uuid-11"},
				{"name": "Bookmark IDP", "uuid_url": "idp-uuid-12"},
				{"name": "SaaS OIDC", "uuid_url": "idp-uuid-13"},
				{"name": "SaaS SAML", "uuid_url": "idp-uuid-14"},
				{"name": "SaaS WSFed", "uuid_url": "idp-uuid-15"},
				{"name": "Health Check IDP", "uuid_url": "idp-uuid-16"},
				{"name": "Load Balancer IDP", "uuid_url": "idp-uuid-17"},
				{"name": "Enterprise Connectivity IDP", "uuid_url": "idp-uuid-18"},
				{"name": "Import IDP", "uuid_url": "idp-uuid-19"},
				{"name": "test-idp", "uuid_url": "idp-uuid-20"},
			},
		}
		respBytes, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBytes))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle connectors endpoint (for GetConnectorUUIDs)
	if strings.Contains(req.URL.Path, "connectors") && req.Method == http.MethodGet {
		m.RLock()
		defer m.RUnlock()
		
		// Return all stored connectors
		var objects []map[string]interface{}
		if m.connectors != nil {
			for name, connectorData := range m.connectors {
				obj := map[string]interface{}{
					"name":     name,
					"uuid_url": connectorData["uuid_url"],
				}
				objects = append(objects, obj)
			}
		}
		
		// Also include default test-agent-01 if not already present
		hasTestAgent := false
		for _, obj := range objects {
			if name, ok := obj["name"].(string); ok && name == "test-agent-01" {
				hasTestAgent = true
				break
			}
		}
		if !hasTestAgent {
			objects = append(objects, map[string]interface{}{
				"name":     "test-agent-01",
				"uuid_url": "test-agent-01-uuid",
			})
		}
		
		resp := map[string]interface{}{
			"meta":    map[string]interface{}{},
			"objects": objects,
		}
		respBytes, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBytes))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle agents endpoint
	// POST /crux/v1/mgmt-pop/agents - Create connector
	if strings.Contains(req.URL.Path, "agents") && req.Method == http.MethodPost {
		m.Lock()
		defer m.Unlock()
		
		// Parse request body to extract connector details
		var createRequest map[string]interface{}
		if req.Body != nil {
			bodyBytes, _ := io.ReadAll(req.Body)
			json.Unmarshal(bodyBytes, &createRequest)
		}
		
		// Extract connector name
		connectorName := "test-connector"
		if name, ok := createRequest["name"].(string); ok {
			connectorName = name
		}
		
		// Generate UUID based on name
		connectorUUID := connectorName + "-uuid"
		
		// Get package value (should be int)
		packageValue := 1 // default
		if pkg, ok := createRequest["package"].(float64); ok {
			packageValue = int(pkg)
		} else if pkg, ok := createRequest["package"].(int); ok {
			packageValue = pkg
		}
		
		// Create connector response
		connector := map[string]interface{}{
			"uuid_url":             connectorUUID,
			"uuid":                 connectorUUID,
			"name":                 connectorName,
			"description":          createRequest["description"],
			"package":              packageValue,
			"state":                1,
			"status":               1,
			"reach":                0,
			"agent_type":           0,
			"debug_channel_permitted": createRequest["debug_channel_permitted"],
			"data_service":         createRequest["data_service"],
			"auth_service":         createRequest["auth_service"],
			"advanced_settings":    createRequest["advanced_settings"],
		}
		
		// Store connector for later retrieval
		if m.connectors == nil {
			m.connectors = make(map[string]map[string]interface{})
		}
		m.connectors[connectorUUID] = connector
		
		respBytes, _ := json.Marshal(connector)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBytes))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// GET /crux/v1/mgmt-pop/agents/{uuid} - Get specific connector
	if strings.Contains(req.URL.Path, "agents/") && req.Method == http.MethodGet && !strings.Contains(req.URL.RawQuery, "offset") {
		// Extract UUID from path (e.g., /crux/v1/mgmt-pop/agents/test-connector-uuid)
		parts := strings.Split(req.URL.Path, "/")
		var connectorUUID string
		for i, p := range parts {
			if p == "agents" && i+1 < len(parts) {
				connectorUUID = parts[i+1]
				break
			}
		}
		
		m.RLock()
		defer m.RUnlock()
		
		// Try to find connector by UUID
		if m.connectors != nil {
			if connector, ok := m.connectors[connectorUUID]; ok {
				respBytes, _ := json.Marshal(connector)
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(string(respBytes))),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			}
		}
		
		// Fallback: return a default connector if not found
		// Try to extract name from UUID (format: name-uuid)
		connectorName := connectorUUID
		if strings.HasSuffix(connectorUUID, "-uuid") {
			connectorName = strings.TrimSuffix(connectorUUID, "-uuid")
		}
		
		connector := map[string]interface{}{
			"uuid_url":             connectorUUID,
			"uuid":                 connectorUUID,
			"name":                 connectorName,
			"package":              7, // Default to aws_classic (7) for test-connector
			"state":                1,
			"status":               1,
			"reach":                0,
			"agent_type":           0,
			"debug_channel_permitted": true,
			"data_service":         false,
			"auth_service":         false,
			"advanced_settings": map[string]interface{}{
				"network_info": []string{"192.168.1.0/24"},
			},
		}
		respBytes, _ := json.Marshal(connector)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBytes))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// GET /crux/v1/mgmt-pop/agents?offset=... - List agents (for GetConnectorUUIDs with pagination)
	if strings.Contains(req.URL.Path, "agents") && req.Method == http.MethodGet {
		// Extract offset from query parameters
		offset := 0
		limit := 100 // Default limit
		if req.URL.RawQuery != "" {
			for _, q := range strings.Split(req.URL.RawQuery, "&") {
				if strings.HasPrefix(q, "offset=") {
					offset, _ = strconv.Atoi(strings.TrimPrefix(q, "offset="))
				}
				if strings.HasPrefix(q, "limit=") {
					limit, _ = strconv.Atoi(strings.TrimPrefix(q, "limit="))
				}
			}
		}
		
		m.RLock()
		defer m.RUnlock()
		
		// Build list from stored connectors and default test connectors
		allConnectors := []map[string]interface{}{
			{
				"name":     "test-connector-01",
				"uuid_url": "test-connector-01",
			},
			{
				"name":     "test-connector-02",
				"uuid_url": "test-connector-02",
			},
		}
		
		// Add stored connectors
		if m.connectors != nil {
			for _, connector := range m.connectors {
				allConnectors = append(allConnectors, map[string]interface{}{
					"name":     connector["name"],
					"uuid_url": connector["uuid_url"],
				})
			}
		}
		
		// Pagination: if offset > 0, return empty to signal end of pagination
		objects := allConnectors
		if offset > 0 {
			objects = []map[string]interface{}{}
		}
		
		resp := map[string]interface{}{
			"meta": map[string]interface{}{
				"total_count": len(allConnectors), // Total across all pages
				"offset":      offset,
				"limit":       limit,
				"next":        nil, // No more pages
				"previous":    nil,
			},
			"objects": objects,
		}
		respBytes, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBytes))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle appcategories endpoint (for data source tests)
	if strings.Contains(req.URL.Path, "appcategories") && req.Method == http.MethodGet {
		resp := map[string]interface{}{
			"meta": map[string]interface{}{},
			"objects": []map[string]interface{}{
				{"name": "category-1", "uuid_url": "category-uuid-1"},
				{"name": "category-2", "uuid_url": "category-uuid-2"},
			},
		}
		respBytes, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBytes))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle pops endpoint (for data source tests)
	if strings.Contains(req.URL.Path, "pops") && req.Method == http.MethodGet {
		resp := map[string]interface{}{
			"meta": map[string]interface{}{},
			"objects": []map[string]interface{}{
				{"name": "pop-1", "region": "us-east-1", "uuid_url": "pop-uuid-1"},
				{"name": "pop-2", "region": "us-west-1", "uuid_url": "pop-uuid-2"},
			},
		}
		respBytes, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBytes))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle access rules endpoint - MUST come before services check
	// Path format: /crux/v1/mgmt-pop/services/{service_uuid}/rules
	if strings.HasSuffix(req.URL.Path, "/rules") && strings.Contains(req.URL.Path, "mgmt-pop/services/") && req.Method == http.MethodGet {
		resp := map[string]interface{}{
			"meta":    map[string]interface{}{},
			"objects": []map[string]interface{}{},
		}
		respBytes, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBytes))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle app services endpoint - MUST come before apps check
	// Path format: /crux/v1/mgmt-pop/apps/{app_uuid}/services
	if strings.HasSuffix(req.URL.Path, "/services") && strings.Contains(req.URL.Path, "mgmt-pop/apps/") && req.Method == http.MethodGet {
		resp := map[string]interface{}{
			"objects": []map[string]interface{}{
				{
					"uuid_url": "service-uuid-access",
					"status":   1,
					"service": map[string]interface{}{
						"name":         "Access Control",
						"uuid_url":     "service-uuid-access",
						"service_type": 6, // SERVICE_TYPE_ACCESS_CTRL = 6 (WAF=1, ACCELERATION=2, AV=3, IPS=4, SLB=5, ACCESS_CTRL=6)
						"status":       "enabled",
					},
				},
			},
		}
		respBytes, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBytes))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle app agents endpoint
	// Path format: /crux/v1/mgmt-pop/apps/{app_uuid}/agents
	if strings.HasSuffix(req.URL.Path, "/agents") && strings.Contains(req.URL.Path, "mgmt-pop/apps/") {
		// Extract app UUID from path
		appUUID := ""
		parts := strings.Split(req.URL.Path, "/")
		for i, p := range parts {
			if p == "apps" && i+1 < len(parts) {
				appUUID = parts[i+1]
				break
			}
		}
		
		if req.Method == http.MethodGet {
			m.RLock()
			defer m.RUnlock()
			
			// Return stored agents for this app
			var agents []map[string]interface{}
			if m.appAgents != nil {
				if appAgentList, ok := m.appAgents[appUUID]; ok {
					for _, agentName := range appAgentList {
						agents = append(agents, map[string]interface{}{
							"agent": map[string]interface{}{
								"name":     agentName,
								"uuid_url": agentName + "-uuid",
							},
						})
					}
				}
			}
			
			resp := map[string]interface{}{
				"meta":    map[string]interface{}{},
				"objects": agents,
			}
			respBytes, _ := json.Marshal(resp)
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(string(respBytes))),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		} else if req.Method == http.MethodPost {
			// Store agents when they're assigned
			m.Lock()
			defer m.Unlock()
			
			if m.appAgents == nil {
				m.appAgents = make(map[string][]string)
			}
			
			// Parse request body to get agents
			var assignRequest map[string]interface{}
			if req.Body != nil {
				bodyBytes, _ := io.ReadAll(req.Body)
				json.Unmarshal(bodyBytes, &assignRequest)
				req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			}
			
			// Extract agent UUIDs from request and map them to names
			var agentNames []string
			if agentsList, ok := assignRequest["agents"].([]interface{}); ok {
				for _, agent := range agentsList {
					if agentMap, ok := agent.(map[string]interface{}); ok {
						if uuid, ok := agentMap["uuid_url"].(string); ok {
							// Map UUID to name by checking connectors map
							agentName := ""
							if m.connectors != nil {
								for name, connectorData := range m.connectors {
									if connUUID, ok := connectorData["uuid_url"].(string); ok && connUUID == uuid {
										agentName = name
										break
									}
								}
							}
							// If UUID format is "name-uuid", extract name
							if agentName == "" && strings.HasSuffix(uuid, "-uuid") {
								agentName = strings.TrimSuffix(uuid, "-uuid")
							}
							// Default to UUID if name not found
							if agentName == "" {
								agentName = uuid
							}
							agentNames = append(agentNames, agentName)
						}
					}
				}
			}
			
			// Store agents for this app
			m.appAgents[appUUID] = agentNames
			
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(`{"status": "success"}`)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}
	}
	// Handle appdirectories endpoint (assign directories to app)
	// Path format: /crux/v1/mgmt-pop/appdirectories
	if strings.Contains(req.URL.Path, "appdirectories") && req.Method == http.MethodPost {
		m.Lock()
		defer m.Unlock()
		
		if m.appDirectories == nil {
			m.appDirectories = make(map[string]map[string][]string)
		}
		
		// Parse request body to get app and directories
		var assignRequest map[string]interface{}
		if req.Body != nil {
			bodyBytes, _ := io.ReadAll(req.Body)
			json.Unmarshal(bodyBytes, &assignRequest)
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		
		// Extract app UUID and directories from request
		if dataList, ok := assignRequest["data"].([]interface{}); ok && len(dataList) > 0 {
			if dataMap, ok := dataList[0].(map[string]interface{}); ok {
				if appsList, ok := dataMap["apps"].([]interface{}); ok && len(appsList) > 0 {
					appUUID := appsList[0].(string)
					if dirsList, ok := dataMap["directories"].([]interface{}); ok {
						if m.appDirectories[appUUID] == nil {
							m.appDirectories[appUUID] = make(map[string][]string)
						}
						for _, dir := range dirsList {
							if dirMap, ok := dir.(map[string]interface{}); ok {
								if dirUUID, ok := dirMap["uuid_url"].(string); ok {
									// Map UUID to name (format: "name-uuid")
									dirName := strings.TrimSuffix(dirUUID, "-uuid")
									if dirName == "" {
										dirName = "Cloud Directory" // Default
									}
									// Initialize empty groups list for this directory
									if m.appDirectories[appUUID][dirName] == nil {
										m.appDirectories[appUUID][dirName] = []string{}
									}
								}
							}
						}
					}
				}
			}
		}
		
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(`{"status": "success"}`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle appgroups endpoint (assign groups to app)
	// Path format: /crux/v1/mgmt-pop/appgroups
	if strings.Contains(req.URL.Path, "appgroups") && req.Method == http.MethodPost {
		m.Lock()
		defer m.Unlock()
		
		if m.appDirectories == nil {
			m.appDirectories = make(map[string]map[string][]string)
		}
		
		// Parse request body to get app and groups
		var assignRequest map[string]interface{}
		if req.Body != nil {
			bodyBytes, _ := io.ReadAll(req.Body)
			json.Unmarshal(bodyBytes, &assignRequest)
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		
		// Extract app UUID and groups from request
		if dataList, ok := assignRequest["data"].([]interface{}); ok && len(dataList) > 0 {
			if dataMap, ok := dataList[0].(map[string]interface{}); ok {
				if appsList, ok := dataMap["apps"].([]interface{}); ok && len(appsList) > 0 {
					appUUID := appsList[0].(string)
					if groupsList, ok := dataMap["groups"].([]interface{}); ok {
						if m.appDirectories[appUUID] == nil {
							m.appDirectories[appUUID] = make(map[string][]string)
						}
						// For now, store groups in a default directory
						// In a real implementation, we'd need to look up the directory from the group UUID
						dirName := "Cloud Directory" // Default directory name
						if m.appDirectories[appUUID][dirName] == nil {
							m.appDirectories[appUUID][dirName] = []string{}
						}
						for _, group := range groupsList {
							if groupMap, ok := group.(map[string]interface{}); ok {
								if groupUUID, ok := groupMap["uuid_url"].(string); ok {
									// Map UUID to name (format: "name-uuid")
									groupName := strings.TrimSuffix(groupUUID, "-uuid")
									if groupName == "" {
										continue
									}
									// Add group to directory if not already present
									found := false
									for _, g := range m.appDirectories[appUUID][dirName] {
										if g == groupName {
											found = true
											break
										}
									}
									if !found {
										m.appDirectories[appUUID][dirName] = append(m.appDirectories[appUUID][dirName], groupName)
									}
								}
							}
						}
					}
				}
			}
		}
		
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(`{"status": "success"}`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle app directories_membership endpoint
	// Path format: /crux/v1/mgmt-pop/apps/{app_uuid}/directories_membership
	if strings.HasSuffix(req.URL.Path, "/directories_membership") && strings.Contains(req.URL.Path, "mgmt-pop/apps/") && req.Method == http.MethodGet {
		// Extract app UUID from path
		appUUID := ""
		parts := strings.Split(req.URL.Path, "/")
		for i, p := range parts {
			if p == "apps" && i+1 < len(parts) {
				appUUID = parts[i+1]
				break
			}
		}
		
		m.RLock()
		defer m.RUnlock()
		
		// Return stored directories for this app
		var directories []map[string]interface{}
		if m.appDirectories != nil {
			if appDirs, ok := m.appDirectories[appUUID]; ok {
				for dirName := range appDirs {
					dirMembership := map[string]interface{}{
						"directory": map[string]interface{}{
							"name":             dirName,
							"directory_uuid_url": dirName + "-uuid",
						},
					}
					directories = append(directories, dirMembership)
				}
			}
		}
		
		resp := map[string]interface{}{
			"meta":    map[string]interface{}{},
			"objects": directories,
		}
		respBytes, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBytes))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle app groups endpoint
	// Path format: /crux/v1/mgmt-pop/apps/{app_uuid}/groups
	if strings.HasSuffix(req.URL.Path, "/groups") && strings.Contains(req.URL.Path, "mgmt-pop/apps/") && req.Method == http.MethodGet {
		// Extract app UUID from path
		appUUID := ""
		parts := strings.Split(req.URL.Path, "/")
		for i, p := range parts {
			if p == "apps" && i+1 < len(parts) {
				appUUID = parts[i+1]
				break
			}
		}
		
		m.RLock()
		defer m.RUnlock()
		
		// Return stored groups for this app
		var groupMemberships []map[string]interface{}
		if m.appDirectories != nil {
			if appDirs, ok := m.appDirectories[appUUID]; ok {
				for dirName, groupNames := range appDirs {
					for _, groupName := range groupNames {
						groupMembership := map[string]interface{}{
							"group": map[string]interface{}{
								"name":           groupName,
								"dir_name":       dirName,
								"dir_uuid_url":   dirName + "-uuid",
								"group_uuid_url": groupName + "-uuid",
							},
						}
						groupMemberships = append(groupMemberships, groupMembership)
					}
				}
			}
		}
		
		resp := map[string]interface{}{
			"meta":    map[string]interface{}{},
			"objects": groupMemberships,
		}
		respBytes, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBytes))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle app idp_membership endpoint
	// Path format: /crux/v1/mgmt-pop/apps/{app_uuid}/idp_membership
	if strings.HasSuffix(req.URL.Path, "/idp_membership") && strings.Contains(req.URL.Path, "mgmt-pop/apps/") && req.Method == http.MethodGet {
		resp := map[string]interface{}{
			"meta":    map[string]interface{}{},
			"objects": []map[string]interface{}{
				{
					"idp": map[string]interface{}{
						"name":     "test-idp",
						"uuid_url": "idp-uuid-20",
					},
				},
			},
		}
		respBytes, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBytes))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle app deploy endpoint
	// Path format: /crux/v1/mgmt-pop/apps/{app_uuid}/deploy
	if strings.HasSuffix(req.URL.Path, "/deploy") && strings.Contains(req.URL.Path, "mgmt-pop/apps/") && req.Method == http.MethodPost {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("{}")),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle appidp endpoint (assign IDP to app)
	// Path format: /crux/v1/mgmt-pop/appidp
	if strings.Contains(req.URL.Path, "mgmt-pop/appidp") && req.Method == http.MethodPost {
		m.Lock()
		defer m.Unlock()
		
		if m.appIDPs == nil {
			m.appIDPs = make(map[string]string)
		}
		
		// Parse request body to get app and IDP
		var assignRequest map[string]interface{}
		if req.Body != nil {
			bodyBytes, _ := io.ReadAll(req.Body)
			json.Unmarshal(bodyBytes, &assignRequest)
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		
		// Extract app UUID and IDP UUID
		if appUUID, ok := assignRequest["app"].(string); ok {
			if idpUUID, ok := assignRequest["idp"].(string); ok {
				// Look up IDP name from UUID (default to "test-idp" if not found)
				idpName := "test-idp"
				// Try to find IDP name from stored IDPs
				if m.idps != nil {
					for name, idpData := range m.idps {
						if uuid, ok := idpData["uuid_url"].(string); ok && uuid == idpUUID {
							idpName = name
							break
						}
					}
				} else {
					// Initialize idps map if needed
					m.idps = make(map[string]map[string]interface{})
					// Add default test-idp
					m.idps["test-idp"] = map[string]interface{}{
						"name":     "test-idp",
						"uuid_url": idpUUID,
					}
				}
				m.appIDPs[appUUID] = idpName
			}
		}
		
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("{}")),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle v3 apps endpoint (for GetApps with pagination)
	// Path: /crux/v3/mgmt-pop/apps?limit=10&offset=0&fields=name,uuid_url&ordering=name
	if strings.Contains(req.URL.Path, "crux/v3/mgmt-pop/apps") && req.Method == http.MethodGet {
		// Extract offset and limit from query parameters
		offset := 0
		limit := 10 // Default limit for v3 API
		if req.URL.RawQuery != "" {
			for _, q := range strings.Split(req.URL.RawQuery, "&") {
				if strings.HasPrefix(q, "offset=") {
					offset, _ = strconv.Atoi(strings.TrimPrefix(q, "offset="))
				}
				if strings.HasPrefix(q, "limit=") {
					limit, _ = strconv.Atoi(strings.TrimPrefix(q, "limit="))
				}
			}
		}
		
		// Return mock apps that match the test fixture names
		objects := []map[string]interface{}{
			{
				"name":     "test-app-01",
				"uuid_url": "app-uuid-test-app-01",
			},
			{
				"name":     "test-app-02",
				"uuid_url": "app-uuid-test-app-02",
			},
		}
		
		// Pagination: if offset > 0, return empty to signal end of pagination
		if offset > 0 {
			objects = []map[string]interface{}{}
		}
		
		resp := map[string]interface{}{
			"meta": map[string]interface{}{
				"total_count": len(objects),
				"offset":      offset,
				"limit":       limit,
				"next":        nil, // No more pages
				"previous":    nil,
			},
			"objects": objects,
		}
		respBytes, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBytes))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle v3 apps endpoint (for GetApps with pagination)
	// Path: /crux/v3/mgmt-pop/apps?limit=10&offset=0&fields=name,uuid_url&ordering=name
	if strings.Contains(req.URL.Path, "crux/v3/mgmt-pop/apps") && req.Method == http.MethodGet {
		// Extract offset and limit from query parameters
		offset := 0
		limit := 10 // Default limit for v3 API
		if req.URL.RawQuery != "" {
			for _, q := range strings.Split(req.URL.RawQuery, "&") {
				if strings.HasPrefix(q, "offset=") {
					offset, _ = strconv.Atoi(strings.TrimPrefix(q, "offset="))
				}
				if strings.HasPrefix(q, "limit=") {
					limit, _ = strconv.Atoi(strings.TrimPrefix(q, "limit="))
				}
			}
		}
		
		// Return mock apps that match the test fixture names
		allApps := []map[string]interface{}{
			{
				"name":     "test-app-01",
				"uuid_url": "app-uuid-test-app-01",
			},
			{
				"name":     "test-app-02",
				"uuid_url": "app-uuid-test-app-02",
			},
		}
		
		// Pagination: if offset > 0, return empty to signal end of pagination
		objects := allApps
		if offset > 0 {
			objects = []map[string]interface{}{}
		}
		
		resp := map[string]interface{}{
			"meta": map[string]interface{}{
				"total_count": len(allApps), // Total across all pages
				"offset":      offset,
				"limit":       limit,
				"next":        nil, // No more pages
				"previous":    nil,
			},
			"objects": objects,
		}
		respBytes, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBytes))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Handle apps endpoint (for application creation)
	if strings.Contains(req.URL.Path, "mgmt-pop/apps") {
		if req.Method == http.MethodPost {
			m.Lock()
			defer m.Unlock()
			
			// Parse request body to extract app data
			var createRequest map[string]interface{}
			appName := "test-app"
			if req.Body != nil {
				bodyBytes, _ := io.ReadAll(req.Body)
				json.Unmarshal(bodyBytes, &createRequest)
				if name, ok := createRequest["name"].(string); ok {
					appName = name
				}
				// Recreate body for potential later use
				req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			}
			
			appUUID := "app-uuid-" + appName
			
			// Store app data for GET requests
			if m.apps == nil {
				m.apps = make(map[string]map[string]interface{})
			}
			
			// Build app response with all fields from request
			appData := map[string]interface{}{
				"uuid_url":    appUUID,
				"name":        appName,
				"app_status":  1,
				"app_type":    1,
				"app_profile": 1,
				"status":      1,
			}
			
			// Copy all fields from create request
			for k, v := range createRequest {
				appData[k] = v
			}
			
			// Override with proper types and defaults
			if desc, ok := createRequest["description"].(string); ok {
				appData["description"] = desc
			}
			if host, ok := createRequest["host"].(string); ok {
				appData["host"] = host
			}
			// Domain: convert from int/float64/string if needed, default to 1 (wapp)
			// Domain can come as int, float64, or string "wapp"/"custom"
			if domain, ok := createRequest["domain"].(int); ok {
				appData["domain"] = domain
			} else if domain, ok := createRequest["domain"].(float64); ok {
				appData["domain"] = int(domain)
			} else if domain, ok := createRequest["domain"].(string); ok {
				// Convert string to int: "wapp" = 1, "custom" = 2
				if domain == "wapp" {
					appData["domain"] = 1
				} else if domain == "custom" {
					appData["domain"] = 2
				} else {
					appData["domain"] = 1 // Default to wapp
				}
			} else {
				appData["domain"] = 1 // Default to wapp
			}
			// Client app mode: convert from int/float64 if needed, default to 1 (tcp)
			if clientAppMode, ok := createRequest["client_app_mode"].(int); ok {
				appData["client_app_mode"] = clientAppMode
			} else if clientAppMode, ok := createRequest["client_app_mode"].(float64); ok {
				appData["client_app_mode"] = int(clientAppMode)
			} else {
				appData["client_app_mode"] = 1 // Default to tcp
			}
			// Popregion: default to us-east-1 if not set
			if _, ok := appData["popregion"]; !ok {
				appData["popregion"] = "us-east-1"
			}
			// Auth enabled: default to "true" if not set
			if _, ok := appData["auth_enabled"]; !ok {
				appData["auth_enabled"] = "true"
			}
			// Servers: default to empty array if not set (will be populated by separate API call)
			if _, ok := appData["servers"]; !ok {
				appData["servers"] = []map[string]interface{}{}
			}
			// Advanced settings: ensure request_parameters is present
			if advancedSettings, ok := appData["advanced_settings"].(map[string]interface{}); ok {
				if _, ok := advancedSettings["request_parameters"]; !ok {
					advancedSettings["request_parameters"] = map[string]interface{}{}
				}
				appData["advanced_settings"] = advancedSettings
			} else {
				// Default advanced_settings based on app name
				appAuth := "SAML2.0"
				if strings.Contains(appName, "kerberos") {
					appAuth = "kerberos"
				} else if strings.Contains(appName, "tunnel") || strings.Contains(appName, "bookmark") {
					appAuth = "basic"
				}
				appData["advanced_settings"] = map[string]interface{}{
					"app_auth":          appAuth,
					"request_parameters": map[string]interface{}{},
				}
			}
			
			// Detect app type from name to set appropriate flags
			isKerberos := strings.Contains(appName, "kerberos")
			isTunnel := strings.Contains(appName, "tunnel") || strings.Contains(appName, "health-check")
			isBookmark := strings.Contains(appName, "bookmark")
			isSaaS := strings.Contains(appName, "saas")
			samlEnabled := !isKerberos && !isTunnel && !isBookmark
			
			appData["saml"] = samlEnabled
			appData["saml_settings"] = []map[string]interface{}{}
			appData["oidc"] = false
			appData["oidc_settings"] = nil
			appData["oidcclients"] = []interface{}{}
			appData["wsfed"] = false
			appData["wsfed_settings"] = []map[string]interface{}{}
			appData["app_deployed"] = false
			appData["app_operational"] = 0
			
			// Set app_category only if not saas
			if !isSaaS {
				appData["app_category"] = nil
			}
			
			// Store app data
			m.apps[appUUID] = appData
			
			respBytes, _ := json.Marshal(appData)
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(string(respBytes))),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}
		if req.Method == http.MethodPut || req.Method == http.MethodPatch {
			// Handle app update - extract UUID and update stored data
			appUUID := ""
			parts := strings.Split(req.URL.Path, "/")
			for i, p := range parts {
				if p == "apps" && i+1 < len(parts) {
					appUUID = parts[i+1]
					break
				}
			}
			
			m.Lock()
			defer m.Unlock()
			
			// Parse update request
			var updateRequest map[string]interface{}
			if req.Body != nil {
				bodyBytes, _ := io.ReadAll(req.Body)
				json.Unmarshal(bodyBytes, &updateRequest)
				req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			}
			
			// Initialize apps map if needed
			if m.apps == nil {
				m.apps = make(map[string]map[string]interface{})
			}
			
			// Get existing app data or create new
			appData, ok := m.apps[appUUID]
			if !ok {
				appData = make(map[string]interface{})
				appData["uuid_url"] = appUUID
			}
			
			// Update with new data, ensuring proper types
			for k, v := range updateRequest {
				// Convert domain from string to int if needed
				if k == "domain" {
					if domainStr, ok := v.(string); ok {
						if domainStr == "wapp" {
							appData[k] = 1
						} else if domainStr == "custom" {
							appData[k] = 2
						} else {
							appData[k] = 1 // Default to wapp
						}
					} else {
						appData[k] = v
					}
				} else if k == "saml_settings" {
					// Store saml_settings as-is (array of maps)
					// But filter out default/empty blocks when storing to prevent them from being returned
					if samlSettings, ok := v.([]interface{}); ok {
						filteredSAMLSettings := []map[string]interface{}{}
						for _, samlSetting := range samlSettings {
							if samlMap, ok := samlSetting.(map[string]interface{}); ok {
								filteredSAML := make(map[string]interface{})
								// Copy idp if present
								if idp, ok := samlMap["idp"].(map[string]interface{}); ok && len(idp) > 0 {
									filteredSAML["idp"] = idp
								}
								// Only include sp if it has entity_id or acs_url
								if spRaw, ok := samlMap["sp"]; ok {
									var sp map[string]interface{}
									if spMap, ok := spRaw.(map[string]interface{}); ok {
										sp = spMap
									} else if spArray, ok := spRaw.([]interface{}); ok && len(spArray) > 0 {
										if spMap, ok := spArray[0].(map[string]interface{}); ok {
											sp = spMap
										}
									}
									if sp != nil && len(sp) > 0 {
										// Check if sp has meaningful values (entity_id or acs_url)
										// If both are empty/missing, exclude sp (even if it has token_life or other fields)
										entityID, hasEntityID := sp["entity_id"].(string)
										acsURL, hasACSURL := sp["acs_url"].(string)
										// Only include if at least one is set and non-empty
										// Note: token_life is not a valid field for SAML SPConfig, so ignore it
										if (hasEntityID && entityID != "") || (hasACSURL && acsURL != "") {
											filteredSAML["sp"] = sp
										}
										// Otherwise exclude sp (it only has defaults like token_life=0 or empty entity_id/acs_url)
									}
								}
								// Only include subject if it's not default
								if subjectRaw, ok := samlMap["subject"]; ok {
									var subject map[string]interface{}
									if subjectMap, ok := subjectRaw.(map[string]interface{}); ok {
										subject = subjectMap
									} else if subjectArray, ok := subjectRaw.([]interface{}); ok && len(subjectArray) > 0 {
										if subjectMap, ok := subjectArray[0].(map[string]interface{}); ok {
											subject = subjectMap
										}
									}
									if subject != nil && len(subject) > 0 {
										fmtVal, hasFmt := subject["fmt"].(string)
										srcVal, hasSrc := subject["src"].(string)
										if !(hasFmt && hasSrc && fmtVal == "email" && srcVal == "user.email") {
											filteredSAML["subject"] = subject
										}
									}
								}
								// Copy attrmap if present
								if attrmap, ok := samlMap["attrmap"].([]interface{}); ok && len(attrmap) > 0 {
									filteredSAML["attrmap"] = attrmap
								}
								if len(filteredSAML) > 0 {
									filteredSAMLSettings = append(filteredSAMLSettings, filteredSAML)
								}
							}
						}
						appData[k] = filteredSAMLSettings
					} else {
						appData[k] = v
					}
				} else if k == "servers" {
					// Store servers as-is (array of maps)
					appData[k] = v
				} else {
					appData[k] = v
				}
			}
			
			// Store updated data
			m.apps[appUUID] = appData
			
			respBytes, _ := json.Marshal(appData)
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(string(respBytes))),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}
		if req.Method == http.MethodGet {
			// Extract app UUID from path
			appUUID := ""
			parts := strings.Split(req.URL.Path, "/")
			for i, p := range parts {
				if p == "apps" && i+1 < len(parts) {
					appUUID = parts[i+1]
					break
				}
			}
			
			m.RLock()
			defer m.RUnlock()
			
			// Return stored app data if available
			if m.apps != nil {
				if appData, ok := m.apps[appUUID]; ok {
					// Make a copy to avoid race conditions and ensure proper types
					appDataCopy := make(map[string]interface{})
					for k, v := range appData {
						// Ensure domain is always an int
						if k == "domain" {
							if domainStr, ok := v.(string); ok {
								if domainStr == "wapp" {
									appDataCopy[k] = 1
								} else if domainStr == "custom" {
									appDataCopy[k] = 2
								} else {
									appDataCopy[k] = 1
								}
							} else {
								appDataCopy[k] = v
							}
						} else {
							appDataCopy[k] = v
						}
					}
					// Ensure required fields are present with defaults
					if _, ok := appDataCopy["domain"]; !ok {
						appDataCopy["domain"] = 1
					}
					if _, ok := appDataCopy["client_app_mode"]; !ok {
						appDataCopy["client_app_mode"] = 1
					}
					if _, ok := appDataCopy["popregion"]; !ok {
						appDataCopy["popregion"] = "us-east-1"
					}
					if _, ok := appDataCopy["auth_enabled"]; !ok {
						appDataCopy["auth_enabled"] = "true"
					}
					// Ensure servers and saml_settings are arrays (not nil)
					if _, ok := appDataCopy["servers"]; !ok {
						appDataCopy["servers"] = []map[string]interface{}{}
					}
					// Filter saml_settings to remove empty/default blocks
					// Handle both []interface{} and []map[string]interface{} types
					var samlSettings []interface{}
					if samlSettingsRaw, ok := appDataCopy["saml_settings"]; ok {
						if samlSettingsList, ok := samlSettingsRaw.([]interface{}); ok {
							samlSettings = samlSettingsList
						} else if samlSettingsMapList, ok := samlSettingsRaw.([]map[string]interface{}); ok {
							// Convert []map[string]interface{} to []interface{}
							samlSettings = make([]interface{}, len(samlSettingsMapList))
							for i, v := range samlSettingsMapList {
								samlSettings[i] = v
							}
						}
					}
					if samlSettings != nil && len(samlSettings) > 0 {
						filteredSAMLSettings := []map[string]interface{}{}
						for _, samlSetting := range samlSettings {
							if samlMap, ok := samlSetting.(map[string]interface{}); ok {
								filteredSAML := make(map[string]interface{})
								// Only include non-empty blocks
								if idp, ok := samlMap["idp"].(map[string]interface{}); ok && len(idp) > 0 {
									filteredSAML["idp"] = idp
								}
								// Only include sp if it has meaningful values (entity_id or acs_url set)
								// DefaultSAMLConfig has empty entity_id and acs_url, so if both are empty, exclude sp
								// Also exclude if sp only has default values like token_life=0
								// sp can be a map or an array containing a map
								if spRaw, ok := samlMap["sp"]; ok {
									var sp map[string]interface{}
									// Handle both map and array-of-map formats
									if spMap, ok := spRaw.(map[string]interface{}); ok {
										sp = spMap
									} else if spArray, ok := spRaw.([]interface{}); ok && len(spArray) > 0 {
										if spMap, ok := spArray[0].(map[string]interface{}); ok {
											sp = spMap
										}
									}
									
									if sp != nil && len(sp) > 0 {
										// Check if sp has meaningful values (entity_id or acs_url)
										// If both are empty/missing, exclude sp (even if it has token_life or other fields)
										entityID, hasEntityID := sp["entity_id"].(string)
										acsURL, hasACSURL := sp["acs_url"].(string)
										// Only include if at least one is set and non-empty
										if (hasEntityID && entityID != "") || (hasACSURL && acsURL != "") {
											// Store as map (not array) to match what Terraform expects after unmarshaling
											filteredSAML["sp"] = sp
										}
										// Otherwise exclude sp (it only has defaults like token_life=0)
									}
								}
								// Only include subject if it's not the default (fmt="email", src="user.email")
								// DefaultSAMLConfig has fmt="email" and src="user.email", so exclude if both match
								// Also exclude if subject is empty or has no meaningful values
								if subjectRaw, ok := samlMap["subject"]; ok {
									var subject map[string]interface{}
									if subjectMap, ok := subjectRaw.(map[string]interface{}); ok {
										subject = subjectMap
									} else if subjectArray, ok := subjectRaw.([]interface{}); ok && len(subjectArray) > 0 {
										if subjectMap, ok := subjectArray[0].(map[string]interface{}); ok {
											subject = subjectMap
										}
									}
									if subject != nil {
										// Check if subject is empty
										if len(subject) > 0 {
											fmtVal, hasFmt := subject["fmt"].(string)
											srcVal, hasSrc := subject["src"].(string)
											// Exclude if it matches the default values exactly or if both are empty/missing
											if !(hasFmt && hasSrc && fmtVal == "email" && srcVal == "user.email") && (hasFmt || hasSrc) {
												// Include if it's not the default and has at least one value
												filteredSAML["subject"] = subject
											}
										}
									}
								}
								if attrmap, ok := samlMap["attrmap"].([]interface{}); ok && len(attrmap) > 0 {
									filteredSAML["attrmap"] = attrmap
								}
								if len(filteredSAML) > 0 {
									filteredSAMLSettings = append(filteredSAMLSettings, filteredSAML)
								}
							}
						}
						appDataCopy["saml_settings"] = filteredSAMLSettings
					} else if _, ok := appDataCopy["saml_settings"]; !ok {
						appDataCopy["saml_settings"] = []map[string]interface{}{}
					}
					respBytes, _ := json.Marshal(appDataCopy)
					return &http.Response{
						StatusCode: 200,
						Body:       io.NopCloser(strings.NewReader(string(respBytes))),
						Header:     make(http.Header),
						Request:    req,
					}, nil
				}
			}
			
			// Fallback: build response from UUID
			appName := appUUID
			if strings.HasPrefix(appUUID, "app-uuid-") {
				appName = strings.TrimPrefix(appUUID, "app-uuid-")
			}
			
			// Detect app type from name
			isKerberos := strings.Contains(appName, "kerberos")
			isTunnel := strings.Contains(appName, "tunnel") || strings.Contains(appName, "health-check")
			isBookmark := strings.Contains(appName, "bookmark")
			isSaaS := strings.Contains(appName, "saas")
			appAuth := "SAML2.0"
			if isKerberos {
				appAuth = "kerberos"
			} else if isTunnel || isBookmark {
				appAuth = "basic"
			}
			
			advancedSettings := map[string]interface{}{
				"app_auth":          appAuth,
				"request_parameters": map[string]interface{}{},
			}
			
			samlEnabled := !isKerberos && !isTunnel && !isBookmark
			resp := map[string]interface{}{
				"uuid_url":          appUUID,
				"name":              appName,
				"app_status":        1,
				"app_type":          1,
				"app_profile":       1,
				"status":            1,
				"auth_enabled":      "true",
				"advanced_settings": advancedSettings,
				"saml":              samlEnabled,
				"saml_settings":     []map[string]interface{}{},
				"oidc":              false,
				"oidc_settings":     nil,
				"oidcclients":       []interface{}{},
				"wsfed":             false,
				"wsfed_settings":    []map[string]interface{}{},
				"servers":           []map[string]interface{}{},
				"app_deployed":      false,
				"app_operational":   0,
				"domain":            1,
				"client_app_mode":   1,
			}
			
			if !isSaaS {
				resp["app_category"] = nil
			}
			
			respBytes, _ := json.Marshal(resp)
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(string(respBytes))),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}
		if req.Method == http.MethodDelete {
			return &http.Response{
				StatusCode: 204,
				Body:       io.NopCloser(strings.NewReader("{}")),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}
	}
	// Default mock response
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("{}")),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// createMockEaaClient creates a mock EAA client with mocked HTTP transport
func createMockEaaClient(mockTransport *MockHTTPTransport) *client.EaaClient {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:  hclog.Info,
		Output: io.Discard,
	})
	mockHTTPClient := &http.Client{
		Transport: mockTransport,
	}
	mockSigner := &client.MockSigner{}
	return &client.EaaClient{
		ContractID: "test-contract",
		Client:     mockHTTPClient,
		Signer:     mockSigner,
		Host:       "test.example.com",
		Logger:     logger,
	}
}

// Global provider instance reused across tests to avoid repeated gRPC initialization
var globalTestProvider *schema.Provider
var globalTestProviderOnce sync.Once

// getGlobalTestProvider returns a singleton provider instance for tests
// This avoids repeated gRPC initialization and reduces goroutine leaks
func getGlobalTestProvider() *schema.Provider {
	globalTestProviderOnce.Do(func() {
		globalMockTransport := &MockHTTPTransport{
			Responses:      make(map[string]MockResponse),
			connectors:     make(map[string]map[string]interface{}),
			connectorPools: make(map[string]map[string]interface{}),
		}
		globalTestProvider = Provider()
		globalTestProvider.ConfigureContextFunc = func(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
			mockClient := createMockEaaClient(globalMockTransport)
			return mockClient, nil
		}
	})
	return globalTestProvider
}

// UnitTestProviderFactories returns provider factories for unit tests
// These use mocked clients that don't make real API calls
// Provider instance is reused to avoid repeated gRPC initialization
func UnitTestProviderFactories() map[string]func() (*schema.Provider, error) {
	return map[string]func() (*schema.Provider, error){
		"eaa": func() (*schema.Provider, error) {
			// Reuse global provider instance to avoid repeated gRPC initialization
			return getGlobalTestProvider(), nil
		},
	}
}

// TestProviderFactories returns provider factories for resource.Test
// Uses the same shared provider instance to avoid spawning multiple plugin servers
// This is the recommended approach to avoid goroutine leaks from terraform-exec
func TestProviderFactories() map[string]func() (*schema.Provider, error) {
	return UnitTestProviderFactories() // Reuse the same shared provider
}

// testSemaphore limits concurrent resource.UnitTest calls
// This prevents goroutine leaks when many tests run in parallel
// resource.UnitTest spawns terraform-exec processes that create gRPC goroutines
// Limiting to 4 concurrent tests prevents goroutine accumulation
var testSemaphore = make(chan struct{}, 4)

// AcquireTestLock acquires a semaphore slot to limit concurrent resource.UnitTest calls
// This prevents too many terraform-exec processes from running simultaneously
func AcquireTestLock() {
	testSemaphore <- struct{}{}
}

// ReleaseTestLock releases the semaphore slot and performs cleanup
func ReleaseTestLock() {
	<-testSemaphore
	
	// Cleanup: Remove Terraform cache to prevent accumulation
	// This helps prevent goroutine leaks from stale terraform-exec processes
	cleanupTerraformCache()
}

// cleanupTerraformCache removes Terraform plugin cache to prevent accumulation
// This helps prevent goroutine leaks from stale terraform-exec processes
func cleanupTerraformCache() {
	// Get Terraform cache directory
	cacheDir := filepath.Join(os.TempDir(), ".terraform")
	if cacheDir == "" {
		// Fallback to default Terraform cache location
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return
		}
		cacheDir = filepath.Join(homeDir, ".terraform.d", "plugin-cache")
	}
	
	// Try to remove cache directory (ignore errors - it's best effort cleanup)
	_ = os.RemoveAll(cacheDir)
	
	// Kill hanging terraform-exec and test processes with timeout to prevent blocking
	// Use a goroutine with timeout to prevent this from blocking test execution
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		
		// Kill terraform-exec processes
		cmd := exec.CommandContext(ctx, "pkill", "-f", "terraform-exec")
		_ = cmd.Run()
		
		// Kill any hanging test processes (they shouldn't exist, but clean up if they do)
		cmd2 := exec.CommandContext(ctx, "pkill", "-9", "-f", "eaaprovider.test")
		_ = cmd2.Run()
	}()
}

