package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// RegistrationToken represents a registration token for a connector pool
type RegistrationToken struct {
	UUIDURL             string   `json:"uuid_url,omitempty"`
	Name                string   `json:"name"`
	MaxUse              int      `json:"max_use"`
	ConnectorPool       string   `json:"connector_pool"`
	Agents              []string `json:"agents,omitempty"`
	ExpiresAt           string   `json:"expires_at"`
	ImageURL            string   `json:"image_url,omitempty"`
	Token               string   `json:"token,omitempty"`
	UsedCount           int      `json:"used_count,omitempty"`
	TokenSuffix         string   `json:"token_suffix,omitempty"`
	ModifiedAt          string   `json:"modified_at,omitempty"`
	GenerateEmbeddedImg bool     `json:"generate_embedded_img,omitempty"`
}

// MetaResponse represents the meta information in API responses
type MetaResponse struct {
	TotalCount int     `json:"total_count"`
	Offset     int     `json:"offset"`
	Limit      int     `json:"limit"`
	Next       *string `json:"next"`
	Previous   *string `json:"previous"`
}

// RegistrationTokenResponse represents the API response for registration tokens
type RegistrationTokenResponse struct {
	Meta    MetaResponse        `json:"meta"`
	Objects []RegistrationToken `json:"objects"`
}

// CreateRegistrationTokenRequest represents the request to create a registration token
type CreateRegistrationTokenRequest struct {
	Name                string `json:"name"`
	MaxUse              int    `json:"max_use"`
	ExpiresAt           string `json:"expires_at"`
	ConnectorPool       string `json:"connector_pool"`
	GenerateEmbeddedImg bool   `json:"generate_embedded_img"`
}



// CreateRegistrationTokenRequestFromSchema creates a CreateRegistrationTokenRequest from Terraform schema data
func (r *CreateRegistrationTokenRequest) CreateRegistrationTokenRequestFromSchema(ctx context.Context, d *schema.ResourceData, client *EaaClient) error {
	// Get the registration tokens from the schema
	tokens, ok := d.GetOk("registration_tokens")
	if !ok {
		return fmt.Errorf("no registration tokens found in schema")
	}

	tokensList := tokens.([]interface{})
	if len(tokensList) == 0 {
		return fmt.Errorf("registration tokens list is empty")
	}

	// For now, we'll use the first token in the list
	// In a real implementation, you might want to handle multiple tokens differently
	tokenData := tokensList[0].(map[string]interface{})

	// Validate and set the token name
	tokenName, err := ValidateRequiredString(d, "registration_tokens.0.name", client)
	if err != nil {
		return fmt.Errorf("failed to validate token name: %w", err)
	}
	r.Name = tokenName

	// Set max_use (optional, default to 1 if not specified)
	if maxUseRaw, ok := tokenData["max_use"]; ok {
		maxUse, err := ValidateTokenField(maxUseRaw, "max_use", 1, 1000, client)
		if err != nil {
			return err
		}
		r.MaxUse = maxUse
	} else {
		r.MaxUse = 1 // Default value
	}

	// Set expires_in_days and calculate expires_at
	if expiresInDaysRaw, ok := tokenData["expires_in_days"]; ok {
		expiresInDays, err := ValidateTokenField(expiresInDaysRaw, "expires_in_days", 1, 700, client)
		if err != nil {
			return err
		}
		
		now := time.Now().UTC()
		expiresAt := now.AddDate(0, 0, expiresInDays)
		r.ExpiresAt = expiresAt.Format(time.RFC3339)
	} else {
		// Default to 30 days if not specified
		now := time.Now().UTC()
		expiresAt := now.AddDate(0, 0, 30)
		r.ExpiresAt = expiresAt.Format(time.RFC3339)
	}

	// Set connector pool (this will be set by the caller)
	// r.ConnectorPool = poolUUID

	// Set generate_embedded_img (optional, default to false)
	if generateEmbeddedImg, ok := tokenData["generate_embedded_img"].(bool); ok {
		r.GenerateEmbeddedImg = generateEmbeddedImg
	} else {
		r.GenerateEmbeddedImg = false // Default value
	}

	return nil
}

// CreateRegistrationToken creates a new registration token
func (r *CreateRegistrationTokenRequest) CreateRegistrationToken(ctx context.Context, client *EaaClient) (*RegistrationToken, error) {
	// Create the registration token via API
	body, err := r.createTokenViaAPI(client)
	if err != nil {
		return nil, err
	}

	// Parse and find the created token
	return r.parseAndFindToken(client, body)
}

// createTokenViaAPI handles the API call to create the registration token
func (r *CreateRegistrationTokenRequest) createTokenViaAPI(client *EaaClient) ([]byte, error) {
	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_URL)

	// Make the API call using SendAPIRequest
	resp, err := client.SendAPIRequest(apiURL, http.MethodPost, r, nil, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create registration token: %w", err)
	}

	client.Logger.Info("Response status:", resp.StatusCode)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		errorDetail, _ := FormatErrorResponse(resp)
		return nil, fmt.Errorf("failed to create registration token: %s", errorDetail)
	}

	// For create operations, we typically don't get a response body
	// If we need to get the created token, we fetch it from the list
	client.Logger.Info("=== CREATE OPERATION COMPLETE - FETCHING TOKENS ===")
	return r.fetchTokensFromList(client)
}

// fetchTokensFromList fetches the list of tokens when the create response is empty
func (r *CreateRegistrationTokenRequest) fetchTokensFromList(client *EaaClient) ([]byte, error) {
	client.Logger.Info("=== EMPTY RESPONSE BODY - FETCHING TOKENS ===")

	// Add a small delay to ensure the token is fully created
	time.Sleep(100 * time.Millisecond)

	// Fetch the list of tokens for this connector pool
	listURL := fmt.Sprintf("%s://%s/%s?connector_pool_id=%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_GET_URL, r.ConnectorPool)

	var response RegistrationTokenResponse
	resp, err := client.SendAPIRequest(listURL, http.MethodGet, nil, &response, false)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch registration tokens: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		errorDetail, _ := FormatErrorResponse(resp)
		return nil, fmt.Errorf("failed to fetch registration tokens: %s", errorDetail)
	}

	// Convert the parsed response back to JSON for logging
	body, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	client.Logger.Info("=== FETCHED TOKENS RESPONSE ===")
	client.Logger.Info("Response Status:", resp.StatusCode)
	client.Logger.Info("Response Body:", string(body))
	client.Logger.Info("=== END FETCHED TOKENS ===")

	return body, nil
}

// parseAndFindToken parses the response and finds the created token
func (r *CreateRegistrationTokenRequest) parseAndFindToken(client *EaaClient, body []byte) (*RegistrationToken, error) {
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

	// Find exact matches first
	exactMatches := r.findExactMatches(listResponse.Objects, client)
	if len(exactMatches) > 0 {
		client.Logger.Info("=== EXACT MATCHES ===")
		client.Logger.Info("Total exact matches found:", len(exactMatches))
		for i, token := range exactMatches {
			client.Logger.Info(fmt.Sprintf("Exact match %d - Name: %s, UUID: %s", i+1, token.Name, token.UUIDURL))
		}
		client.Logger.Info("=== END EXACT MATCHES ===")
		return exactMatches[0], nil
	}

	// If no exact matches, look for name match
	return r.findTokenByName(listResponse.Objects, client)
}

// findExactMatches finds tokens that exactly match our request
func (r *CreateRegistrationTokenRequest) findExactMatches(tokens []RegistrationToken, client *EaaClient) []*RegistrationToken {
	var exactMatches []*RegistrationToken
	
	for i := range tokens {
		token := &tokens[i]

		// Normalize expires_at field to handle timezone format differences
		requestedExpiresAt := r.normalizeExpiresAt(r.ExpiresAt)
		tokenExpiresAt := r.normalizeExpiresAt(token.ExpiresAt)

		// Check if this token matches our request
		if token.Name == r.Name &&
			token.MaxUse == r.MaxUse &&
			token.ConnectorPool == r.ConnectorPool &&
			token.GenerateEmbeddedImg == r.GenerateEmbeddedImg &&
			requestedExpiresAt == tokenExpiresAt {
			exactMatches = append(exactMatches, token)
		}
	}

	return exactMatches
}

// findTokenByName finds a token by name when no exact matches are found
func (r *CreateRegistrationTokenRequest) findTokenByName(tokens []RegistrationToken, client *EaaClient) (*RegistrationToken, error) {
	client.Logger.Info("=== NO EXACT MATCHES - LOOKING FOR NAME MATCH ===")
	
	for i := range tokens {
		token := &tokens[i]
		if token.Name == r.Name {
			client.Logger.Info("Found token with matching name:", token.Name, "UUID:", token.UUIDURL)
			return token, nil
		}
	}
	
	client.Logger.Error("=== NO TOKEN FOUND WITH MATCHING NAME ===")
	return nil, fmt.Errorf("no registration token found with matching name: %s", r.Name)
}

// normalizeExpiresAt normalizes the expires_at field to handle timezone format differences
func (r *CreateRegistrationTokenRequest) normalizeExpiresAt(expiresAt string) string {
	// Remove milliseconds and normalize timezone format
	if len(expiresAt) > 5 && expiresAt[len(expiresAt)-5:] == ".000Z" {
		return expiresAt[:len(expiresAt)-5] + "Z"
	}
	return expiresAt
}

// GetRegistrationTokens retrieves all registration tokens for a connector pool
func (client *EaaClient) GetRegistrationTokens(connectorPool string) ([]RegistrationToken, error) {
	listURL := fmt.Sprintf("%s://%s/%s?connector_pool_id=%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_GET_URL, connectorPool)

	client.Logger.Info("=== GET ALL REGISTRATION TOKENS ===")
	client.Logger.Info("Connector Pool UUID:", connectorPool)
	client.Logger.Info("API URL:", listURL)

	var response RegistrationTokenResponse
	resp, err := client.SendAPIRequest(listURL, http.MethodGet, nil, &response, false)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch registration tokens: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		errorDetail, _ := FormatErrorResponse(resp)
		return nil, fmt.Errorf("failed to fetch registration tokens: %s", errorDetail)
	}

	// Convert the parsed response back to JSON for logging
	body, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	client.Logger.Info("=== COMPLETE GET ALL TOKENS API RESPONSE ===")
	client.Logger.Info("Response Status:", resp.StatusCode)
	client.Logger.Info("Response Body:", string(body))
	client.Logger.Info("=== END GET ALL TOKENS API RESPONSE ===")

	return response.Objects, nil
}

// GetRegistrationTokenByUUID retrieves a registration token by UUID
func (client *EaaClient) GetRegistrationTokenByUUID(uuidURL, connectorPool string) (*RegistrationToken, error) {
	listURL := fmt.Sprintf("%s://%s/%s?connector_pool_id=%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_GET_URL, connectorPool)

	client.Logger.Info("=== GET REGISTRATION TOKENS BY CONNECTOR POOL ===")
	client.Logger.Info("Connector Pool UUID:", connectorPool)
	client.Logger.Info("Looking for Token UUID:", uuidURL)
	client.Logger.Info("API URL:", listURL)

	var response RegistrationTokenResponse
	resp, err := client.SendAPIRequest(listURL, http.MethodGet, nil, &response, false)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch registration tokens: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		errorDetail, _ := FormatErrorResponse(resp)
		return nil, fmt.Errorf("failed to fetch registration tokens: %s", errorDetail)
	}

	// Convert the parsed response back to JSON for logging
	body, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	client.Logger.Info("=== COMPLETE GET API RESPONSE ===")
	client.Logger.Info("Response Status:", resp.StatusCode)
	client.Logger.Info("Response Body:", string(body))
	client.Logger.Info("=== END RESPONSE ===")

	client.Logger.Info("=== SEARCHING FOR TOKEN ===")
	client.Logger.Info("Total tokens found:", len(response.Objects))

	// Find the token by UUID
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

// DeleteRegistrationTokenByUUID deletes a registration token by its UUID
func DeleteRegistrationTokenByUUID(ctx context.Context, client *EaaClient, tokenUUID string) error {
	// Construct the URL for deleting the specific token
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_URL, tokenUUID)

	client.Logger.Info("=== DELETE REGISTRATION TOKEN ===")
	client.Logger.Info("Token UUID:", tokenUUID)
	client.Logger.Info("API URL:", apiURL)

	// Make the DELETE request
	resp, err := client.SendAPIRequest(apiURL, http.MethodDelete, nil, nil, false)
	if err != nil {
		return fmt.Errorf("failed to delete registration token: %w", err)
	}

	client.Logger.Info("Delete response status:", resp.StatusCode)

	// Check if the deletion was successful
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		errorDetail, _ := FormatErrorResponse(resp)
		return fmt.Errorf("failed to delete registration token: %s", errorDetail)
	}

	client.Logger.Info("=== SUCCESSFULLY DELETED REGISTRATION TOKEN ===")
	return nil
}

// CreateRegistrationTokensFromSchema creates registration tokens for a connector pool from Terraform schema
func CreateRegistrationTokensFromSchema(ctx context.Context, d *schema.ResourceData, eaaclient *EaaClient, poolUUID string) error {
	tokens, ok := d.GetOk("registration_tokens")
	if !ok {
		return nil
	}

	tokensList := tokens.([]interface{})
	for _, tokenInterface := range tokensList {
		tokenData := tokenInterface.(map[string]interface{})

		// Validate max_use and expires_in_days fields
		maxUse, err := ValidateTokenField(tokenData["max_use"], "max_use", 1, 1000, eaaclient)
		if err != nil {
			return err
		}

		expiresInDays, err2 := ValidateTokenField(tokenData["expires_in_days"], "expires_in_days", 1, 700, eaaclient)
		if err2 != nil {
			return err2
		}

		// Convert expires_in_days to RFC3339 format in UTC
		now := time.Now().UTC()
		expiresAt := now.AddDate(0, 0, expiresInDays).Format(time.RFC3339)

		createTokenRequest := CreateRegistrationTokenRequest{
			Name:                tokenData["name"].(string),
			MaxUse:              maxUse,
			ExpiresAt:           expiresAt,
			ConnectorPool:       poolUUID,
			GenerateEmbeddedImg: tokenData["generate_embedded_img"].(bool),
		}

		_, err3 := createTokenRequest.CreateRegistrationToken(ctx, eaaclient)
		if err3 != nil {
			eaaclient.Logger.Error("Failed to create registration token:", err3)
			return fmt.Errorf("failed to create registration token: %w", err3)
		}
	}

	return nil
} 