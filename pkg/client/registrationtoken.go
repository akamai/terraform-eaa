package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// RegistrationToken represents a registration token
type RegistrationToken struct {
	UUIDURL            string    `json:"uuid_url,omitempty"`
	Name               string    `json:"name"`
	MaxUse             int       `json:"max_use"`
	ConnectorPool      string    `json:"connector_pool"`
	Agents             []string  `json:"agents,omitempty"`
	ExpiresAt          string    `json:"expires_at"`
	ImageURL           string    `json:"image_url,omitempty"`
	Token              string    `json:"token,omitempty"`
	UsedCount          int       `json:"used_count,omitempty"`
	TokenSuffix        string    `json:"token_suffix,omitempty"`
	ModifiedAt         string    `json:"modified_at,omitempty"`
	GenerateEmbeddedImg bool     `json:"generate_embedded_img,omitempty"`
}

// RegistrationTokenResponse represents the response from the registration token API
type RegistrationTokenResponse struct {
	Meta    MetaResponse       `json:"meta"`
	Objects []RegistrationToken `json:"objects"`
}

// MetaResponse represents the meta information in API responses
type MetaResponse struct {
	TotalCount int    `json:"total_count"`
	Offset     int    `json:"offset"`
	Limit      int    `json:"limit"`
	Next       *string `json:"next"`
	Previous   *string `json:"previous"`
}

// CreateRegistrationTokenRequest represents the request to create a registration token
type CreateRegistrationTokenRequest struct {
	Name               string `json:"name"`
	MaxUse             int    `json:"max_use"`
	ExpiresAt          string `json:"expires_at"`
	ConnectorPool      string `json:"connector_pool"`
	GenerateEmbeddedImg bool  `json:"generate_embedded_img"`
}

// CreateRegistrationTokenRequestFromSchema creates a CreateRegistrationTokenRequest from Terraform schema
func (r *CreateRegistrationTokenRequest) CreateRegistrationTokenRequestFromSchema(ctx context.Context, d *schema.ResourceData, client *EaaClient) error {
	r.Name = d.Get("name").(string)
	r.MaxUse = d.Get("max_use").(int)
	r.ExpiresAt = d.Get("expires_at").(string)
	r.ConnectorPool = d.Get("connector_pool").(string)
	r.GenerateEmbeddedImg = d.Get("generate_embedded_img").(bool)
	return nil
}

// CreateRegistrationToken creates a new registration token
func (r *CreateRegistrationTokenRequest) CreateRegistrationToken(ctx context.Context, client *EaaClient, contractID, gid string) (*RegistrationToken, error) {
	apiURL := fmt.Sprintf("%s://%s/%s?contractId=%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_URL, contractID)
	
	// Make the API call without parsing the response
	resp, err := client.SendAPIRequest(apiURL, http.MethodPost, r, nil, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create registration token: %w", err)
	}
	
	// Log the response status and body for debugging
	client.Logger.Info("Response status:", resp.StatusCode)
	
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		errorDetail, _ := FormatErrorResponse(resp)
		return nil, fmt.Errorf("failed to create registration token: %s", errorDetail)
	}
	
	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	
	// Log the complete response body for debugging
	client.Logger.Info("=== COMPLETE CREATE API RESPONSE ===")
	client.Logger.Info("Response Status:", resp.StatusCode)
	client.Logger.Info("Response Body:", string(body))
	client.Logger.Info("=== END CREATE API RESPONSE ===")
	
	if len(body) == 0 {
			// If response body is empty, we need to fetch the created token from the list
	client.Logger.Info("=== EMPTY RESPONSE BODY - FETCHING TOKENS ===")
	
	// Add a small delay to ensure the token is fully created and has a unique timestamp
	time.Sleep(100 * time.Millisecond)
	
	// Fetch the list of tokens for this connector pool to find the one we just created
	listURL := fmt.Sprintf("%s://%s/%s?connector_pool_id=%s&contractId=%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_GET_URL, r.ConnectorPool, contractID)
		
		resp, err := client.SendAPIRequest(listURL, http.MethodGet, nil, nil, true)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch registration tokens: %w", err)
		}
		
		if resp.StatusCode != http.StatusOK {
			errorDetail, _ := FormatErrorResponse(resp)
			return nil, fmt.Errorf("failed to fetch registration tokens: %s", errorDetail)
		}
		
		// Read the response body
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}
		
		client.Logger.Info("=== FETCHED TOKENS RESPONSE ===")
		client.Logger.Info("Response Status:", resp.StatusCode)
		client.Logger.Info("Response Body:", string(body))
		client.Logger.Info("=== END FETCHED TOKENS ===")
	}
	
	// Parse the response as list format (API always returns list)
	var listResponse RegistrationTokenResponse
	if err := json.Unmarshal(body, &listResponse); err != nil {
		client.Logger.Error("Failed to parse as list format. Error:", err)
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	client.Logger.Info("=== PARSED AS LIST FORMAT ===")
	client.Logger.Info("Total tokens in response:", len(listResponse.Objects))
	for i, token := range listResponse.Objects {
		client.Logger.Info(fmt.Sprintf("Token %d - Name: %s, UUID: %s, ConnectorPool: %s", i+1, token.Name, token.UUIDURL, token.ConnectorPool))
	}
	client.Logger.Info("=== END LIST FORMAT ===")
	
	if len(listResponse.Objects) == 0 {
		return nil, fmt.Errorf("no registration token returned from API")
	}
	
	// Strictly match on all unique fields
	var exactMatches []*RegistrationToken
	for i := range listResponse.Objects {
		token := &listResponse.Objects[i];
		
		// Normalize expires_at field to handle timezone format differences
		requestedExpiresAt := r.ExpiresAt
		tokenExpiresAt := token.ExpiresAt
		
		// Remove milliseconds and normalize timezone format
		if len(requestedExpiresAt) > 5 && requestedExpiresAt[len(requestedExpiresAt)-5:] == ".000Z" {
			requestedExpiresAt = requestedExpiresAt[:len(requestedExpiresAt)-5] + "Z"
		}
		if len(tokenExpiresAt) > 5 && tokenExpiresAt[len(tokenExpiresAt)-5:] == ".000Z" {
			tokenExpiresAt = tokenExpiresAt[:len(tokenExpiresAt)-5] + "Z"
		}
		
		// Debug logging for timezone normalization
		client.Logger.Info(fmt.Sprintf("=== COMPARING TOKEN %d ===", i+1))
		client.Logger.Info("Original requested ExpiresAt:", r.ExpiresAt)
		client.Logger.Info("Normalized requested ExpiresAt:", requestedExpiresAt)
		client.Logger.Info("Original token ExpiresAt:", token.ExpiresAt)
		client.Logger.Info("Normalized token ExpiresAt:", tokenExpiresAt)
		client.Logger.Info("Name match:", token.Name == r.Name)
		client.Logger.Info("ConnectorPool match:", token.ConnectorPool == r.ConnectorPool)
		client.Logger.Info("MaxUse match:", token.MaxUse == r.MaxUse)
		client.Logger.Info("ExpiresAt match:", tokenExpiresAt == requestedExpiresAt)
		client.Logger.Info("=== END COMPARISON ===")
		
		if token.Name == r.Name &&
		   token.ConnectorPool == r.ConnectorPool &&
		   token.MaxUse == r.MaxUse &&
		   tokenExpiresAt == requestedExpiresAt {
			exactMatches = append(exactMatches, token)
		}
	}

	if len(exactMatches) == 1 {
		client.Logger.Info("=== STRICT MATCH FOUND ===")
		client.Logger.Info("Selected token - Name:", exactMatches[0].Name, "UUID:", exactMatches[0].UUIDURL, "Token:", exactMatches[0].Token, "ModifiedAt:", exactMatches[0].ModifiedAt)
		client.Logger.Info("=== END STRICT MATCH ===")
		return exactMatches[0], nil
	} else if len(exactMatches) > 1 {
		client.Logger.Error("=== MULTIPLE STRICT MATCHES FOUND ===")
		for i, token := range exactMatches {
			client.Logger.Error(fmt.Sprintf("  Match %d - Name: %s, UUID: %s, Token: %s, MaxUse: %d, ExpiresAt: %s, ModifiedAt: %s", i+1, token.Name, token.UUIDURL, token.Token, token.MaxUse, token.ExpiresAt, token.ModifiedAt))
		}
		client.Logger.Error("=== END MULTIPLE MATCHES ===")
		return nil, fmt.Errorf("multiple registration tokens found with the same unique fields; cannot determine which to use")
	} else {
		client.Logger.Error("=== NO STRICT MATCH FOUND ===")
		client.Logger.Error("Requested token with Name:", r.Name, "ConnectorPool:", r.ConnectorPool, "MaxUse:", r.MaxUse, "ExpiresAt:", r.ExpiresAt)
		client.Logger.Error("Available tokens:")
		for i, token := range listResponse.Objects {
			client.Logger.Error(fmt.Sprintf("  %d. Name: %s, UUID: %s, ConnectorPool: %s, MaxUse: %d, ExpiresAt: %s", i+1, token.Name, token.UUIDURL, token.ConnectorPool, token.MaxUse, token.ExpiresAt))
		}
		client.Logger.Error("=== END NO MATCH ===")
		return nil, fmt.Errorf("no registration token found with the specified unique fields")
	}
}

// GetRegistrationToken retrieves a registration token by ID
func (client *EaaClient) GetRegistrationToken(connectorPool, contractID string) (*RegistrationToken, error) {
	// Use the v3 endpoint to list tokens for the specific connector pool
	listURL := fmt.Sprintf("%s://%s/%s?connector_pool_id=%s&contractId=%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_GET_URL, connectorPool, contractID)
	var response RegistrationTokenResponse
	resp, err := client.SendAPIRequest(listURL, http.MethodGet, nil, &response, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get registration tokens: %w", err)
	}
	
	if resp.StatusCode != http.StatusOK {
		errorDetail, _ := FormatErrorResponse(resp)
		return nil, fmt.Errorf("failed to get registration tokens: %s", errorDetail)
	}
	
	// For now, return the first token found for this connector pool
	// In a real implementation, you might want to filter by name or other criteria
	if len(response.Objects) > 0 {
		return &response.Objects[0], nil
	}
	
	return nil, fmt.Errorf("no registration tokens found for connector pool %s", connectorPool)
}

// GetRegistrationTokenByUUID retrieves a specific registration token by UUID URL
func (client *EaaClient) GetRegistrationTokenByUUID(uuidURL, connectorPool, contractID string) (*RegistrationToken, error) {
	// Use the v3 endpoint to list tokens for the specific connector pool
	// The connectorPool parameter is the UUID of the connector pool
	listURL := fmt.Sprintf("%s://%s/%s?connector_pool_id=%s&contractId=%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_GET_URL, connectorPool, contractID)
	
	client.Logger.Info("=== GET REGISTRATION TOKENS BY CONNECTOR POOL ===")
	client.Logger.Info("Connector Pool UUID:", connectorPool)
	client.Logger.Info("Looking for Token UUID:", uuidURL)
	client.Logger.Info("API URL:", listURL)
	
	// Make the GET request and capture the full response
	resp, err := client.SendAPIRequest(listURL, http.MethodGet, nil, nil, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get registration tokens: %w", err)
	}
	
	if resp.StatusCode != http.StatusOK {
		errorDetail, _ := FormatErrorResponse(resp)
		return nil, fmt.Errorf("failed to get registration tokens: %s", errorDetail)
	}
	
	// Read the complete response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	
	// Log the complete JSON response
	client.Logger.Info("=== COMPLETE GET API RESPONSE ===")
	client.Logger.Info("Response Status:", resp.StatusCode)
	client.Logger.Info("Response Body:", string(body))
	client.Logger.Info("=== END RESPONSE ===")
	
	// Parse the response
	var response RegistrationTokenResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	client.Logger.Info("=== SEARCHING FOR TOKEN ===")
	client.Logger.Info("Total tokens found:", len(response.Objects))
	
	// Find the specific token by UUID URL
	for i, token := range response.Objects {
		client.Logger.Info(fmt.Sprintf("Token %d - UUID: %s, Name: %s", i+1, token.UUIDURL, token.Name))
		if token.UUIDURL == uuidURL {
			client.Logger.Info("=== FOUND MATCHING TOKEN ===")
			client.Logger.Info("Token UUID:", token.UUIDURL)
			client.Logger.Info("Token Name:", token.Name)
			client.Logger.Info("Token Value:", token.Token)
			client.Logger.Info("=== END MATCHING TOKEN ===")
			return &token, nil
		}
	}
	
	client.Logger.Error("=== TOKEN NOT FOUND ===")
	client.Logger.Error("Searched for UUID:", uuidURL)
	client.Logger.Error("In connector pool:", connectorPool)
	client.Logger.Error("Available tokens:")
	for i, token := range response.Objects {
		client.Logger.Error(fmt.Sprintf("  %d. UUID: %s, Name: %s", i+1, token.UUIDURL, token.Name))
	}
	client.Logger.Error("=== END TOKEN NOT FOUND ===")
	
	return nil, fmt.Errorf("registration token with UUID %s not found in connector pool %s", uuidURL, connectorPool)
}

// UpdateRegistrationToken updates an existing registration token
func (r *RegistrationToken) UpdateRegistrationToken(ctx context.Context, client *EaaClient, contractID, gid string) error {
	apiURL := fmt.Sprintf("%s://%s/%s/%s?contractId=%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_URL, r.UUIDURL, contractID)
	
	resp, err := client.SendAPIRequest(apiURL, http.MethodPut, r, nil, true)
	if err != nil {
		return fmt.Errorf("failed to update registration token: %w", err)
	}
	
	if resp.StatusCode != http.StatusOK {
		errorDetail, _ := FormatErrorResponse(resp)
		return fmt.Errorf("failed to update registration token: %s", errorDetail)
	}
	
	return nil
}

// DeleteRegistrationToken deletes a registration token
func DeleteRegistrationToken(ctx context.Context, client *EaaClient, tokenID, contractID, gid string) error {
	apiURL := fmt.Sprintf("%s://%s/%s/%s?contractId=%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_URL, tokenID, contractID)
	
	resp, err := client.SendAPIRequest(apiURL, http.MethodDelete, nil, nil, true)
	if err != nil {
		return fmt.Errorf("failed to delete registration token: %w", err)
	}
	
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		errorDetail, _ := FormatErrorResponse(resp)
		return fmt.Errorf("failed to delete registration token: %s", errorDetail)
	}
	
	return nil
}

// GetRegistrationTokens retrieves all registration tokens for a connector pool
func (client *EaaClient) GetRegistrationTokens(connectorPool, contractID string) ([]RegistrationToken, error) {
	// Use the v3 endpoint to list tokens for the specific connector pool
	listURL := fmt.Sprintf("%s://%s/%s?connector_pool_id=%s&contractId=%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_GET_URL, connectorPool, contractID)
	
	// Make the GET request and capture the full response
	resp, err := client.SendAPIRequest(listURL, http.MethodGet, nil, nil, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get registration tokens: %w", err)
	}
	
	if resp.StatusCode != http.StatusOK {
		errorDetail, _ := FormatErrorResponse(resp)
		return nil, fmt.Errorf("failed to get registration tokens: %s", errorDetail)
	}
	
	// Read the complete response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	
	// Log the complete response body for debugging
	client.Logger.Info("=== COMPLETE GET ALL TOKENS API RESPONSE ===")
	client.Logger.Info("Response Status:", resp.StatusCode)
	client.Logger.Info("Response Body:", string(body))
	client.Logger.Info("=== END GET ALL TOKENS API RESPONSE ===")
	
	// Parse the response
	var response RegistrationTokenResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	// Return all tokens
	return response.Objects, nil
} 