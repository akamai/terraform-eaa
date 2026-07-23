package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// FormatExpiresAt parses an RFC3339 timestamp (including fractional seconds and timezone offsets),
// normalises it to UTC, strips sub-second precision, bumps seconds to 1 if they are 0
// (the API rejects :00 seconds), and returns plain RFC3339 UTC (e.g. "2026-05-30T14:30:01Z").
func FormatExpiresAt(raw string) (string, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagValidate}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return "", logging.Wrapf(err, tags, "invalid RFC3339 timestamp %q", raw)
	}
	if t.Second() == 0 {
		t = t.Add(time.Second)
	}
	return t.UTC().Format(time.RFC3339), nil
}

// RegistrationTokenAgent represents a connector assigned to a registration token.
type RegistrationTokenAgent struct {
	UUIDURL   string `json:"uuid_url"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at,omitempty"`
	Status    int    `json:"status"`
}

// RegistrationToken represents a registration token for a connector pool
type RegistrationToken struct {
	UUIDURL             string                   `json:"uuid_url,omitempty"`
	Name                string                   `json:"name"`
	ConnectorPool       string                   `json:"connector_pool"`
	ExpiresAt           string                   `json:"expires_at"`
	ImageURL            string                   `json:"image_url,omitempty"`
	Token               string                   `json:"token,omitempty"`
	TokenSuffix         string                   `json:"token_suffix,omitempty"`
	ModifiedAt          string                   `json:"modified_at,omitempty"`
	Agents              []RegistrationTokenAgent `json:"agents,omitempty"`
	MaxUse              int                      `json:"max_use"`
	UsedCount           int                      `json:"used_count,omitempty"`
	GenerateEmbeddedImg bool                     `json:"generate_embedded_img,omitempty"`
}

// AgentNames returns the names of the connectors assigned to the token.
func (r *RegistrationToken) AgentNames() []string {
	names := make([]string, len(r.Agents))
	for i, agent := range r.Agents {
		names[i] = agent.Name
	}
	return names
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

// Validate checks that RegistrationTokenWriteRequest fields are non-empty and
// within allowed ranges. ExpiresAt must already be normalised via FormatExpiresAt
// (plain RFC3339 UTC, no fractional seconds); un-normalised values will be rejected.
func (r *RegistrationTokenWriteRequest) Validate() error {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagValidate}
	if r.Name == "" {
		return logging.Errorf(tags, "registration token name cannot be empty")
	}
	if r.ExpiresAt == "" {
		return logging.Errorf(tags, "registration token expires_at cannot be empty")
	}
	t, err := time.Parse(time.RFC3339, r.ExpiresAt)
	if err != nil {
		return logging.Wrapf(err, tags, "expires_at must be a valid RFC3339 timestamp, got %q", r.ExpiresAt)
	}
	if !t.After(time.Now()) {
		return logging.Errorf(tags, "expires_at must be in the future, got %s", r.ExpiresAt)
	}
	if r.MaxUse < 1 || r.MaxUse > 1000 {
		return logging.Errorf(tags, "max_use must be in the range of 1 to 1000, got %d", r.MaxUse)
	}
	return nil
}

// CreateRegistrationTokenRequestFromSchema creates a RegistrationTokenWriteRequest from the first
// registration token in the Terraform schema data. Only the first token block is used.
func (r *RegistrationTokenWriteRequest) CreateRegistrationTokenRequestFromSchema(ctx context.Context, d *schema.ResourceData, client *EaaClient) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagValidate}
	logging.Info(ctx, "validating registration token request from schema", tags)

	// Get the registration tokens from the schema
	tokens, ok := d.GetOk("registration_tokens")
	if !ok {
		return logging.Errorf(tags, "no registration tokens found in schema")
	}

	tokensList, ok := tokens.([]interface{})
	if !ok {
		return logging.Errorf(tags, "registration_tokens must be a list, got %T", tokens)
	}
	if len(tokensList) == 0 {
		return logging.Errorf(tags, "registration tokens list is empty")
	}

	tokenData, ok := tokensList[0].(map[string]interface{})
	if !ok {
		return logging.Errorf(tags, "registration token must be an object, got %T", tokensList[0])
	}

	// Validate and set the token name
	tokenName, err := ValidateRequiredString(ctx, d, "registration_tokens.0.name")
	if err != nil {
		return logging.Wrapf(err, tags, "failed to validate token name")
	}
	r.Name = tokenName

	// Set max_use (optional, default to 1 if not specified)
	if maxUseRaw, exists := tokenData["max_use"]; exists {
		maxUseValue, validateErr := ValidateIntegerField(ctx, maxUseRaw, "max_use", 1, 1000)
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
		return logging.Errorf(tags, "registration token expires_at must be a non-empty RFC3339 string (e.g. 2026-01-02T15:04:05Z)")
	}
	formattedExpiresAt, err := FormatExpiresAt(expiresAtRaw)
	if err != nil {
		return logging.Wrapf(err, tags, "registration token expires_at %q is not valid RFC3339", expiresAtRaw)
	}
	r.ExpiresAt = formattedExpiresAt

	// Set generate_embedded_img (optional, default to false)
	if generateEmbeddedImg, ok := tokenData["generate_embedded_img"].(bool); ok {
		r.GenerateEmbeddedImg = generateEmbeddedImg
	} else {
		r.GenerateEmbeddedImg = false // Default value
	}

	logging.Info(ctx, "registration token request validation succeeded", tags, map[string]any{"name": r.Name})
	return nil
}

// CreateRegistrationToken creates a new registration token
func (r *RegistrationTokenWriteRequest) CreateRegistrationToken(ctx context.Context, client *EaaClient) (*RegistrationToken, error) {
	// Create the registration token via API
	body, err := r.createTokenViaAPI(ctx, client)
	if err != nil {
		return nil, err
	}

	// Parse and find the created token
	return r.parseAndFindToken(ctx, body)
}

// createTokenViaAPI handles the API call to create the registration token
func (r *RegistrationTokenWriteRequest) createTokenViaAPI(ctx context.Context, client *EaaClient) ([]byte, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagCreate}
	logging.Info(ctx, "create registration token starting", tags, map[string]any{"name": r.Name})

	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_URL)

	// Make the API call using SendAPIRequest
	resp, err := client.SendAPIRequest(ctx, apiURL, http.MethodPost, r, nil, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "failed to create registration token")
	}

	logging.Trace(ctx, "create registration token response", tags, map[string]any{"status_code": resp.StatusCode})

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		errorDetail := FormatErrorDescription(resp)
		return nil, logging.Errorf(tags, "failed to create registration token: %s", errorDetail)
	}

	// The create API does not return the token in the response body, so we fetch it from the token list.
	logging.Info(ctx, "create operation complete, fetching tokens", tags)
	return r.fetchTokensFromList(ctx, client)
}

// fetchTokensFromList fetches the created token by listing all tokens for the connector pool.
func (r *RegistrationTokenWriteRequest) fetchTokensFromList(ctx context.Context, client *EaaClient) ([]byte, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagList}
	logging.Debug(ctx, "fetching created token from list", tags)

	// Add a small delay to ensure the token is fully created
	time.Sleep(100 * time.Millisecond)

	// Fetch the list of tokens for this connector pool
	listURL := fmt.Sprintf("%s://%s/%s?connector_pool_id=%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_GET_URL, r.ConnectorPool)

	var response RegistrationTokenResponse
	resp, err := client.SendAPIRequest(ctx, listURL, http.MethodGet, nil, &response, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "failed to fetch registration tokens")
	}

	if resp.StatusCode != http.StatusOK {
		errorDetail := FormatErrorDescription(resp)
		return nil, logging.Errorf(tags, "failed to fetch registration tokens: %s", errorDetail)
	}

	// Convert the parsed response back to JSON
	body, err := json.Marshal(response)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "failed to marshal response")
	}

	logging.Trace(ctx, "fetched tokens response", tags, map[string]any{"status_code": resp.StatusCode, "body_length": len(body)})

	return body, nil
}

// parseAndFindToken parses the response and finds the created token
func (r *RegistrationTokenWriteRequest) parseAndFindToken(ctx context.Context, body []byte) (*RegistrationToken, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagRead}

	// Parse the response as list format (API always returns list)
	var listResponse RegistrationTokenResponse
	if err := json.Unmarshal(body, &listResponse); err != nil {
		return nil, logging.Wrapf(err, tags, "failed to parse response")
	}

	logging.Trace(ctx, "parsed token list", tags, map[string]any{"count": len(listResponse.Objects)})

	if len(listResponse.Objects) == 0 {
		return nil, logging.Errorf(tags, "no registration token returned from API")
	}

	// Find exact matches first
	exactMatches := r.findExactMatches(ctx, listResponse.Objects)
	if len(exactMatches) > 0 {
		logging.Debug(ctx, "found exact match for registration token", tags, map[string]any{"count": len(exactMatches), "uuid": exactMatches[0].UUIDURL})
		return exactMatches[0], nil
	}

	// If no exact matches, look for name match
	return r.findTokenByName(ctx, listResponse.Objects)
}

// findExactMatches finds tokens that exactly match our request
func (r *RegistrationTokenWriteRequest) findExactMatches(ctx context.Context, tokens []RegistrationToken) []*RegistrationToken {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagRead}
	var exactMatches []*RegistrationToken

	normalizeExpiresAt := func(expiresAt string) string {
		normalized, err := FormatExpiresAt(expiresAt)
		if err != nil {
			logging.Warn(ctx, "could not normalize expires_at", tags, map[string]any{"expires_at": expiresAt, "error": err.Error()})
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
func (r *RegistrationTokenWriteRequest) findTokenByName(ctx context.Context, tokens []RegistrationToken) (*RegistrationToken, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagRead}
	logging.Debug(ctx, "no exact matches, looking for name match", tags, map[string]any{"name": r.Name})

	for i := range tokens {
		token := &tokens[i]
		if token.Name == r.Name {
			logging.Debug(ctx, "found token with matching name", tags, map[string]any{"name": token.Name, "uuid": token.UUIDURL})
			return token, nil
		}
	}

	return nil, logging.Errorf(tags, "no registration token found with matching name: %s", r.Name)
}

// GetRegistrationTokens retrieves all registration tokens for a connector pool
func (client *EaaClient) GetRegistrationTokens(ctx context.Context, connectorPool string) ([]RegistrationToken, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagList}
	logging.Info(ctx, "get all registration tokens starting", tags, map[string]any{"connector_pool": connectorPool})

	listURL := fmt.Sprintf("%s://%s/%s?connector_pool_id=%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_GET_URL, connectorPool)

	var response RegistrationTokenResponse
	resp, err := client.SendAPIRequest(ctx, listURL, http.MethodGet, nil, &response, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "failed to fetch registration tokens")
	}

	if resp.StatusCode != http.StatusOK {
		errorDetail := FormatErrorDescription(resp)
		return nil, logging.Errorf(tags, "failed to fetch registration tokens: %s", errorDetail)
	}

	logging.Trace(ctx, "get all registration tokens response", tags, map[string]any{"status_code": resp.StatusCode, "count": len(response.Objects)})

	return response.Objects, nil
}

// GetRegistrationTokenByUUID retrieves a registration token by UUID
func (client *EaaClient) GetRegistrationTokenByUUID(ctx context.Context, uuidURL, connectorPool string) (*RegistrationToken, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagRead}
	logging.Info(ctx, "get registration token by UUID starting", tags, map[string]any{"uuid": uuidURL, "connector_pool": connectorPool})

	listURL := fmt.Sprintf("%s://%s/%s?connector_pool_id=%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_GET_URL, connectorPool)

	var response RegistrationTokenResponse
	resp, err := client.SendAPIRequest(ctx, listURL, http.MethodGet, nil, &response, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "failed to fetch registration tokens")
	}

	if resp.StatusCode != http.StatusOK {
		errorDetail := FormatErrorDescription(resp)
		return nil, logging.Errorf(tags, "failed to fetch registration tokens: %s", errorDetail)
	}

	logging.Trace(ctx, "get registration tokens response", tags, map[string]any{"status_code": resp.StatusCode, "count": len(response.Objects)})

	// Find the token by UUID
	for i := range response.Objects {
		token := &response.Objects[i]
		if token.UUIDURL == uuidURL {
			logging.Debug(ctx, "found matching registration token", tags, map[string]any{"uuid": token.UUIDURL, "name": token.Name})
			return token, nil
		}
	}

	return nil, logging.Errorf(tags, "registration token with UUID %s not found in connector pool %s", uuidURL, connectorPool)
}

// DeleteRegistrationTokenByUUID deletes a registration token by its UUID
func DeleteRegistrationTokenByUUID(ctx context.Context, client *EaaClient, tokenUUID string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagDelete}
	logging.Info(ctx, "delete registration token starting", tags, map[string]any{"uuid": tokenUUID})

	// Construct the URL for deleting the specific token
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_URL, tokenUUID)

	// Make the DELETE request
	resp, err := client.SendAPIRequest(ctx, apiURL, http.MethodDelete, nil, nil, false)
	if err != nil {
		return logging.Wrapf(err, tags, "failed to delete registration token")
	}

	// Check if the deletion was successful
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		errorDetail := FormatErrorDescription(resp)
		return logging.Errorf(tags, "failed to delete registration token: %s", errorDetail)
	}

	logging.Info(ctx, "delete registration token succeeded", tags, map[string]any{"uuid": tokenUUID})
	return nil
}

// UpdateRegistrationToken updates an existing registration token via PUT
func UpdateRegistrationToken(ctx context.Context, client *EaaClient, tokenUUID string, req *RegistrationTokenWriteRequest) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagUpdate}

	if tokenUUID == "" {
		return logging.Errorf(tags, "tokenUUID cannot be empty when updating a registration token")
	}
	if err := req.Validate(); err != nil {
		return logging.Wrapf(err, tags, "invalid update registration token request")
	}

	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, client.Host, REGISTRATION_TOKEN_URL, tokenUUID)

	logging.Info(ctx, "update registration token starting", tags, map[string]any{"uuid": tokenUUID})

	resp, err := client.SendAPIRequest(ctx, apiURL, http.MethodPut, req, nil, false)
	if err != nil {
		return logging.Wrapf(err, tags, "failed to update registration token")
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		errorDetail := FormatErrorDescription(resp)
		return logging.Errorf(tags, "failed to update registration token: %s", errorDetail)
	}

	logging.Info(ctx, "update registration token succeeded", tags, map[string]any{"uuid": tokenUUID})
	return nil
}

// CreateRegistrationTokensFromSchema creates registration tokens for a connector pool from Terraform schema
func CreateRegistrationTokensFromSchema(ctx context.Context, d *schema.ResourceData, eaaclient *EaaClient, poolUUID string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnPool, logging.TagCreate}

	tokens, ok := d.GetOk("registration_tokens")
	if !ok {
		return nil
	}

	tokensList, ok := tokens.([]interface{})
	if !ok {
		return logging.Errorf(tags, "registration_tokens must be a list, got %T", tokens)
	}
	for _, tokenInterface := range tokensList {
		tokenData, ok := tokenInterface.(map[string]interface{})
		if !ok {
			return logging.Errorf(tags, "registration token must be an object, got %T", tokenInterface)
		}

		// Validate max_use and expires_at fields
		maxUse, err := ValidateIntegerField(ctx, tokenData["max_use"], "max_use", 1, 1000)
		if err != nil {
			return err
		}

		expiresAtRaw, ok := tokenData["expires_at"].(string)
		if !ok || expiresAtRaw == "" {
			return logging.Errorf(tags, "registration token expires_at must be a non-empty RFC3339 string (e.g. 2026-01-02T15:04:05Z)")
		}
		formattedExpiresAt, err := FormatExpiresAt(expiresAtRaw)
		if err != nil {
			return logging.Wrapf(err, tags, "registration token expires_at %q is not valid RFC3339", expiresAtRaw)
		}

		tokenName, ok := tokenData["name"].(string)
		if !ok || tokenName == "" {
			return logging.Errorf(tags, "registration token name must be a non-empty string")
		}

		generateEmbeddedImg, ok := tokenData["generate_embedded_img"].(bool)
		if !ok {
			return logging.Errorf(tags, "registration token generate_embedded_img must be a bool")
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
			return logging.Wrapf(err3, tags, "failed to create registration token %q", tokenName)
		}
	}

	return nil
}
