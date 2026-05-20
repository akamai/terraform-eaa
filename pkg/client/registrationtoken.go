package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// FormatExpiresAt parses an RFC3339 timestamp, bumps seconds to 1 if they are 0
// (the API rejects :00 seconds), and returns plain RFC3339 UTC (e.g. "2026-05-30T14:30:01Z").
func FormatExpiresAt(raw string) (string, error) {
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return "", fmt.Errorf("invalid RFC3339 timestamp %q: %w", raw, err)
	}
	if t.Second() == 0 {
		t = t.Add(time.Second)
	}
	return t.UTC().Format(time.RFC3339), nil
}

// RegistrationToken represents a registration token for a connector pool
type RegistrationToken struct {
	UUIDURL             string   `json:"uuid_url,omitempty"`
	Name                string   `json:"name"`
	ConnectorPool       string   `json:"connector_pool"`
	ExpiresAt           string   `json:"expires_at"`
	ImageURL            string   `json:"image_url,omitempty"`
	Token               string   `json:"token,omitempty"`
	TokenSuffix         string   `json:"token_suffix,omitempty"`
	ModifiedAt          string   `json:"modified_at,omitempty"`
	Agents              []string `json:"agents,omitempty"`
	MaxUse              int      `json:"max_use"`
	UsedCount           int      `json:"used_count,omitempty"`
	GenerateEmbeddedImg bool     `json:"generate_embedded_img,omitempty"`
}

// MetaResponse represents the meta information in API responses
type MetaResponse struct {
	Next       *string `json:"next"`
	Previous   *string `json:"previous"`
	TotalCount int     `json:"total_count"`
	Offset     int     `json:"offset"`
	Limit      int     `json:"limit"`
}

// RegistrationTokenResponse represents the API response for registration tokens
type RegistrationTokenResponse struct {
	Objects []RegistrationToken `json:"objects"`
	Meta    MetaResponse        `json:"meta"`
}

// RegistrationTokenWriteRequest represents the request to create or update a registration token.
type RegistrationTokenWriteRequest struct {
	Name                string `json:"name"`
	ExpiresAt           string `json:"expires_at"`
	ConnectorPool       string `json:"connector_pool"`
	MaxUse              int    `json:"max_use"`
	GenerateEmbeddedImg bool   `json:"generate_embedded_img"`
}

// Validate checks that RegistrationTokenWriteRequest fields are valid.
func (r *RegistrationTokenWriteRequest) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("registration token name cannot be empty")
	}
	if r.ExpiresAt == "" {
		return fmt.Errorf("registration token expires_at cannot be empty")
	}
	if t, err := time.Parse(time.RFC3339, r.ExpiresAt); err == nil && !t.After(time.Now()) {
		return fmt.Errorf("expires_at must be in the future, got %s", r.ExpiresAt)
	}
	if r.MaxUse < 1 || r.MaxUse > 1000 {
		return fmt.Errorf("max_use must be in the range of 1 to 1000, got %d", r.MaxUse)
	}
	return nil
}

// CreateRegistrationTokenRequestFromSchema creates a RegistrationTokenWriteRequest from Terraform schema data
func (r *RegistrationTokenWriteRequest) CreateRegistrationTokenRequestFromSchema(ctx context.Context, d *schema.ResourceData, client *EaaClient) error {
	// Get the registration tokens from the schema
	tokens, ok := d.GetOk("registration_tokens")
	if !ok {
		return fmt.Errorf("no registration tokens found in schema")
	}

	tokensList, ok := tokens.([]interface{})
	if !ok {
		return fmt.Errorf("registration_tokens must be a list, got %T", tokens)
	}
	if len(tokensList) == 0 {
		return fmt.Errorf("registration tokens list is empty")
	}

	tokenData, ok := tokensList[0].(map[string]interface{})
	if !ok {
		return fmt.Errorf("registration token must be an object, got %T", tokensList[0])
	}

	// Validate and set the token name
	tokenName, err := ValidateRequiredString(d, "registration_tokens.0.name", client)
	if err != nil {
		return fmt.Errorf("failed to validate token name: %w", err)
	}
	r.Name = tokenName

	// Set max_use (optional, default to 1 if not specified)
	if maxUseRaw, exists := tokenData["max_use"]; exists {
		maxUseValue, validateErr := ValidateIntegerField(maxUseRaw, "max_use", 1, 1000, client)
		if validateErr != nil {
			return validateErr
		}
		r.MaxUse = maxUseValue
	} else {
		r.MaxUse = 1 // Default value
	}

	// Set expires_at (required RFC3339 timestamp)
	expiresAtRaw, ok := tokenData["expires_at"].(string)
	if !ok || expiresAtRaw == "" {
		return fmt.Errorf("registration token expires_at must be a non-empty RFC3339 string (e.g. 2026-01-02T15:04:05Z)")
	}
	formattedExpiresAt, err := FormatExpiresAt(expiresAtRaw)
	if err != nil {
		return fmt.Errorf("registration token expires_at %q is not valid RFC3339 (e.g. 2026-01-02T15:04:05Z): %w", expiresAtRaw, err)
	}
	r.ExpiresAt = formattedExpiresAt

	// Set generate_embedded_img (optional, default to false)
	if generateEmbeddedImg, ok := tokenData["generate_embedded_img"].(bool); ok {
		r.GenerateEmbeddedImg = generateEmbeddedImg
	} else {
		r.GenerateEmbeddedImg = false // Default value
	}

	return nil
}

// CreateRegistrationToken creates a new registration token
func (r *RegistrationTokenWriteRequest) CreateRegistrationToken(ctx context.Context, client *EaaClient) (*RegistrationToken, error) {
	// Create the registration token via API
	body, err := r.createTokenViaAPI(client)
	if err != nil {
		return nil, err
	}

	// Parse and find the created token
	return r.parseAndFindToken(client, body)
}

// createTokenViaAPI handles the API call to create the registration token
func (r *RegistrationTokenWriteRequest) createTokenViaAPI(client *EaaClient) ([]byte, error) {
	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_URL)

	// Make the API call using SendAPIRequest
	resp, err := client.SendAPIRequest(apiURL, http.MethodPost, r, nil, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create registration token: %w", err)
	}

	client.Logger.Info("Response status", "status_code", resp.StatusCode)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		errorDetail := FormatErrorDescription(resp)
		return nil, fmt.Errorf("failed to create registration token: %s", errorDetail)
	}

	// The create API does not return the token in the response body, so we fetch it from the token list.
	client.Logger.Info("=== CREATE OPERATION COMPLETE - FETCHING TOKENS ===")
	return r.fetchTokensFromList(client)
}

// fetchTokensFromList fetches the created token by listing all tokens for the connector pool.
func (r *RegistrationTokenWriteRequest) fetchTokensFromList(client *EaaClient) ([]byte, error) {
	client.Logger.Info("=== FETCHING CREATED TOKEN FROM LIST ===")

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
		errorDetail := FormatErrorDescription(resp)
		return nil, fmt.Errorf("failed to fetch registration tokens: %s", errorDetail)
	}

	// Convert the parsed response back to JSON for logging
	body, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	client.Logger.Info("=== FETCHED TOKENS RESPONSE ===")
	client.Logger.Info("Response Status", "status_code", resp.StatusCode)
	client.Logger.Info("Response Body", "body", string(body))
	client.Logger.Info("=== END FETCHED TOKENS ===")

	return body, nil
}

// parseAndFindToken parses the response and finds the created token
func (r *RegistrationTokenWriteRequest) parseAndFindToken(client *EaaClient, body []byte) (*RegistrationToken, error) {
	// Parse the response as list format (API always returns list)
	var listResponse RegistrationTokenResponse
	if err := json.Unmarshal(body, &listResponse); err != nil {
		client.Logger.Error("Failed to parse as list format", "error", err)
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	client.Logger.Info("=== PARSED AS LIST FORMAT ===")
	client.Logger.Info("Total tokens in response", "count", len(listResponse.Objects))
	for i := range listResponse.Objects {
		token := &listResponse.Objects[i]
		client.Logger.Info("Token info", "index", i+1, "name", token.Name, "uuid", token.UUIDURL, "connector_pool", token.ConnectorPool)
	}
	client.Logger.Info("=== END LIST FORMAT ===")

	if len(listResponse.Objects) == 0 {
		return nil, fmt.Errorf("no registration token returned from API")
	}

	// Find exact matches first
	exactMatches := r.findExactMatches(listResponse.Objects, client)
	if len(exactMatches) > 0 {
		client.Logger.Info("=== EXACT MATCHES ===")
		client.Logger.Info("Total exact matches found", "count", len(exactMatches))
		for i, token := range exactMatches {
			client.Logger.Info("Exact match", "index", i+1, "name", token.Name, "uuid", token.UUIDURL)
		}
		client.Logger.Info("=== END EXACT MATCHES ===")
		return exactMatches[0], nil
	}

	// If no exact matches, look for name match
	return r.findTokenByName(listResponse.Objects, client)
}

// findExactMatches finds tokens that exactly match our request
func (r *RegistrationTokenWriteRequest) findExactMatches(tokens []RegistrationToken, client *EaaClient) []*RegistrationToken {
	var exactMatches []*RegistrationToken

	normalizeExpiresAt := func(expiresAt string) string {
		normalized, err := FormatExpiresAt(expiresAt)
		if err != nil {
			client.Logger.Warn("Could not normalize", "expires_at", expiresAt, "error", err)
			return expiresAt
		}
		return normalized
	}

	for i := range tokens {
		token := &tokens[i]

		// Normalize expires_at field to handle timezone format differences
		requestedExpiresAt := normalizeExpiresAt(r.ExpiresAt)
		tokenExpiresAt := normalizeExpiresAt(token.ExpiresAt)

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
func (r *RegistrationTokenWriteRequest) findTokenByName(tokens []RegistrationToken, client *EaaClient) (*RegistrationToken, error) {
	client.Logger.Info("=== NO EXACT MATCHES - LOOKING FOR NAME MATCH ===")

	for i := range tokens {
		token := &tokens[i]
		if token.Name == r.Name {
			client.Logger.Info("Found token with matching name", "name", token.Name, "uuid", token.UUIDURL)
			return token, nil
		}
	}

	client.Logger.Error("=== NO TOKEN FOUND WITH MATCHING NAME ===")
	return nil, fmt.Errorf("no registration token found with matching name: %s", r.Name)
}

// GetRegistrationTokens retrieves all registration tokens for a connector pool
func (client *EaaClient) GetRegistrationTokens(connectorPool string) ([]RegistrationToken, error) {
	listURL := fmt.Sprintf("%s://%s/%s?connector_pool_id=%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_GET_URL, connectorPool)

	client.Logger.Info("=== GET ALL REGISTRATION TOKENS ===")
	client.Logger.Info("Connector Pool UUID", "uuid", connectorPool)
	client.Logger.Info("API URL", "url", listURL)

	var response RegistrationTokenResponse
	resp, err := client.SendAPIRequest(listURL, http.MethodGet, nil, &response, false)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch registration tokens: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		errorDetail := FormatErrorDescription(resp)
		return nil, fmt.Errorf("failed to fetch registration tokens: %s", errorDetail)
	}

	// Convert the parsed response back to JSON for logging
	body, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	client.Logger.Info("=== COMPLETE GET ALL TOKENS API RESPONSE ===")
	client.Logger.Info("Response Status", "status_code", resp.StatusCode)
	client.Logger.Info("Response Body", "body", string(body))
	client.Logger.Info("=== END GET ALL TOKENS API RESPONSE ===")

	return response.Objects, nil
}

// GetRegistrationTokenByUUID retrieves a registration token by UUID
func (client *EaaClient) GetRegistrationTokenByUUID(uuidURL, connectorPool string) (*RegistrationToken, error) {
	listURL := fmt.Sprintf("%s://%s/%s?connector_pool_id=%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_GET_URL, connectorPool)

	client.Logger.Info("=== GET REGISTRATION TOKENS BY CONNECTOR POOL ===")
	client.Logger.Info("Connector Pool UUID", "uuid", connectorPool)
	client.Logger.Info("Looking for Token UUID", "uuid", uuidURL)
	client.Logger.Info("API URL", "url", listURL)

	var response RegistrationTokenResponse
	resp, err := client.SendAPIRequest(listURL, http.MethodGet, nil, &response, false)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch registration tokens: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		errorDetail := FormatErrorDescription(resp)
		return nil, fmt.Errorf("failed to fetch registration tokens: %s", errorDetail)
	}

	// Convert the parsed response back to JSON for logging
	body, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	client.Logger.Info("=== COMPLETE GET API RESPONSE ===")
	client.Logger.Info("Response Status", "status_code", resp.StatusCode)
	client.Logger.Info("Response Body", "body", string(body))
	client.Logger.Info("=== END RESPONSE ===")

	client.Logger.Info("=== SEARCHING FOR TOKEN ===")
	client.Logger.Info("Total tokens found", "count", len(response.Objects))

	// Find the token by UUID
	for i := range response.Objects {
		token := &response.Objects[i]
		client.Logger.Info("Token info", "index", i+1, "uuid", token.UUIDURL, "name", token.Name)
		if token.UUIDURL == uuidURL {
			client.Logger.Info("=== FOUND MATCHING TOKEN ===")
			client.Logger.Info("Token UUID", "uuid", token.UUIDURL)
			client.Logger.Info("Token Name", "name", token.Name)
			client.Logger.Debug("Token Value", "token", token.Token)
			client.Logger.Info("=== END MATCHING TOKEN ===")
			return token, nil
		}
	}

	client.Logger.Error("=== TOKEN NOT FOUND ===")
	client.Logger.Error("Searched for UUID", "uuid", uuidURL)
	client.Logger.Error("In connector pool", "uuid", connectorPool)
	client.Logger.Error("Available tokens")
	for i := range response.Objects {
		token := &response.Objects[i]
		client.Logger.Error("Available token", "index", i+1, "uuid", token.UUIDURL, "name", token.Name)
	}
	client.Logger.Error("=== END TOKEN NOT FOUND ===")

	return nil, fmt.Errorf("registration token with UUID %s not found in connector pool %s", uuidURL, connectorPool)
}

// DeleteRegistrationTokenByUUID deletes a registration token by its UUID
func DeleteRegistrationTokenByUUID(ctx context.Context, client *EaaClient, tokenUUID string) error {
	// Construct the URL for deleting the specific token
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_URL, tokenUUID)

	client.Logger.Info("=== DELETE REGISTRATION TOKEN ===")
	client.Logger.Info("Token UUID", "uuid", tokenUUID)
	client.Logger.Info("API URL", "url", apiURL)

	// Make the DELETE request
	resp, err := client.SendAPIRequest(apiURL, http.MethodDelete, nil, nil, false)
	if err != nil {
		return fmt.Errorf("failed to delete registration token: %w", err)
	}

	client.Logger.Info("Delete response status", "status_code", resp.StatusCode)

	// Check if the deletion was successful
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		errorDetail := FormatErrorDescription(resp)
		return fmt.Errorf("failed to delete registration token: %s", errorDetail)
	}

	client.Logger.Info("=== SUCCESSFULLY DELETED REGISTRATION TOKEN ===")
	return nil
}

// UpdateRegistrationToken updates an existing registration token via PUT
func UpdateRegistrationToken(ctx context.Context, client *EaaClient, tokenUUID string, req *RegistrationTokenWriteRequest) error {
	if tokenUUID == "" {
		return fmt.Errorf("tokenUUID cannot be empty when updating a registration token")
	}
	if err := req.Validate(); err != nil {
		return fmt.Errorf("invalid update registration token request: %w", err)
	}

	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_URL, tokenUUID)

	client.Logger.Info("=== UPDATE REGISTRATION TOKEN ===")
	client.Logger.Info("Token UUID", "uuid", tokenUUID)
	client.Logger.Info("API URL", "url", apiURL)

	resp, err := client.SendAPIRequest(apiURL, http.MethodPut, req, nil, false)
	if err != nil {
		return fmt.Errorf("failed to update registration token: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		errorDetail := FormatErrorDescription(resp)
		return fmt.Errorf("failed to update registration token: %s", errorDetail)
	}

	client.Logger.Info("=== SUCCESSFULLY UPDATED REGISTRATION TOKEN ===")
	return nil
}

// CreateRegistrationTokensFromSchema creates registration tokens for a connector pool from Terraform schema
func CreateRegistrationTokensFromSchema(ctx context.Context, d *schema.ResourceData, eaaclient *EaaClient, poolUUID string) error {
	tokens, ok := d.GetOk("registration_tokens")
	if !ok {
		return nil
	}

	tokensList, ok := tokens.([]interface{})
	if !ok {
		return fmt.Errorf("registration_tokens must be a list, got %T", tokens)
	}
	for _, tokenInterface := range tokensList {
		tokenData, ok := tokenInterface.(map[string]interface{})
		if !ok {
			return fmt.Errorf("registration token must be an object, got %T", tokenInterface)
		}

		// Validate max_use and expires_at fields
		maxUse, err := ValidateIntegerField(tokenData["max_use"], "max_use", 1, 1000, eaaclient)
		if err != nil {
			return err
		}

		expiresAtRaw, ok := tokenData["expires_at"].(string)
		if !ok || expiresAtRaw == "" {
			return fmt.Errorf("registration token expires_at must be a non-empty RFC3339 string (e.g. 2026-01-02T15:04:05Z)")
		}
		formattedExpiresAt, err := FormatExpiresAt(expiresAtRaw)
		if err != nil {
			return fmt.Errorf("registration token expires_at %q is not valid RFC3339 (e.g. 2026-01-02T15:04:05Z): %w", expiresAtRaw, err)
		}

		tokenName, ok := tokenData["name"].(string)
		if !ok || tokenName == "" {
			return fmt.Errorf("registration token name must be a non-empty string")
		}

		generateEmbeddedImg, ok := tokenData["generate_embedded_img"].(bool)
		if !ok {
			return fmt.Errorf("registration token generate_embedded_img must be a bool")
		}

		createTokenRequest := RegistrationTokenWriteRequest{
			Name:                tokenName,
			MaxUse:              maxUse,
			ExpiresAt:           formattedExpiresAt,
			ConnectorPool:       poolUUID,
			GenerateEmbeddedImg: generateEmbeddedImg,
		}

		_, err3 := createTokenRequest.CreateRegistrationToken(ctx, eaaclient)
		if err3 != nil {
			eaaclient.Logger.Error("Failed to create registration token:", err3)
			return fmt.Errorf("failed to create registration token: %w", err3)
		}
	}

	return nil
}
