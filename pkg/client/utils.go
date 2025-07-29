package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	ErrEmptyKey = errors.New("key is empty")
	ErrNotFound = errors.New("key not found")
)

func SetAttrs(d *schema.ResourceData, AttributeValues map[string]interface{}) error {
	for attr, value := range AttributeValues {
		if err := d.Set(attr, value); err != nil {
			return err
		}
	}
	return nil
}

func SetAdvancedSettings(d *schema.ResourceData, settings AdvancedSettings) error {
	advancedSettingsMap := make(map[string]interface{})

	v := reflect.ValueOf(settings)
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		tag := t.Field(i).Tag.Get("json")
		tagName := strings.Split(tag, ",")[0]

		// Skip fields with empty values
		if field.Kind() == reflect.Ptr && field.IsNil() {
			continue
		}

		if field.Kind() == reflect.Ptr {
			// Dereference pointer fields
			advancedSettingsMap[tagName] = field.Elem().Interface()
		} else {
			advancedSettingsMap[tagName] = field.Interface()
		}
	}

	return d.Set("advanced_settings", advancedSettingsMap)
}

func GetStringValue(key string, d *schema.ResourceData) (string, error) {
	if key == "" {
		return "", fmt.Errorf("%w: %s", ErrEmptyKey, key)
	}

	value, ok := d.GetOk(key)
	if ok {
		str, ok := value.(string)
		if !ok {
			return "", fmt.Errorf("%w: %s, %q", ErrInvalidType, key, "string")
		}

		return str, nil
	}

	return "", fmt.Errorf("%w: %s", ErrNotFound, key)
}

func DifferenceIgnoreCase(slice1, slice2 []string) []string {
	m := make(map[string]bool)
	for _, item := range slice2 {
		m[strings.ToLower(item)] = true
	}

	var diff []string
	for _, item := range slice1 {
		lowerItem := strings.ToLower(item)
		if _, found := m[lowerItem]; !found {
			diff = append(diff, item)
		}
	}
	return diff
}

func UpdateAdvancedSettings(complete *AdvancedSettings_Complete, delta AdvancedSettings) {
	completeVal := reflect.ValueOf(complete).Elem()
	deltaVal := reflect.ValueOf(delta)

	for i := 0; i < deltaVal.NumField(); i++ {
		deltaField := deltaVal.Field(i)
		completeField := completeVal.FieldByName(deltaVal.Type().Field(i).Name)

		if !deltaField.IsValid() || !completeField.IsValid() || !completeField.CanSet() {
			continue
		}

		if completeField.Kind() == reflect.String || completeField.Kind() == reflect.Ptr {
			if deltaField.Kind() == reflect.Ptr && !deltaField.IsNil() {
				completeField.Set(deltaField)
			} else if deltaField.Kind() == reflect.String {
				completeField.Set(deltaField)
			}
		} else if completeField.Kind() == reflect.Slice {
			if deltaField.IsValid() && deltaField.Kind() == reflect.Slice && !deltaField.IsNil() {
				completeField.Set(deltaField)
			}
		}
	}
}

// ============================================================================
// ENUM CONVERSION UTILITIES
// ============================================================================

// ConvertIntToEnumString converts an integer value to its string representation using a converter function
func ConvertIntToEnumString(intValue int, converter func(int) (string, error)) string {
	if intValue == 0 {
		return ""
	}

	if strValue, err := converter(intValue); err == nil {
		return strValue
	}

	// Fallback to integer if conversion fails
	return fmt.Sprintf("%d", intValue)
}

// ConvertIntToEnumStringForDataSource converts an integer value to its string representation for data sources
func ConvertIntToEnumStringForDataSource(intValue int, converter func(int) (string, error)) string {
	return ConvertIntToEnumString(intValue, converter)
}

// ============================================================================
// DATA CONVERSION UTILITIES
// ============================================================================

// ConvertConnectorsToObjects converts JSON connector data to interface slice for schema
// ConnectorSummary represents a simplified connector view for data sources
type ConnectorSummary struct {
	Name           string `json:"name"`
	Package        int    `json:"package"`
	State          int    `json:"state"`
	Status         int    `json:"status"`
	UUIDURL        string `json:"uuid_url"`
	CreatedAt      string `json:"created_at"`
	Description    string `json:"description"`
	LoadStatus     string `json:"load_status"`
	Localization   string `json:"localization"`
	Reach          int    `json:"reach"`
	AgentInfraType int    `json:"agent_infra_type"`
}

// ConvertConnectorsToObjects handles connector objects and returns proper ConnectorSummary structs
func ConvertConnectorsToObjects(connectors json.RawMessage) []ConnectorSummary {
	// Handle empty or null connectors
	if len(connectors) == 0 || string(connectors) == "null" {
		return []ConnectorSummary{}
	}

	// Try to unmarshal as connector objects
	var connectorArray []ConnectorSummary
	if err := json.Unmarshal(connectors, &connectorArray); err == nil {
		return connectorArray
	}

	// If unmarshaling fails, return empty slice
	return []ConnectorSummary{}
}

// ConvertConnectorsToMap converts connector objects to map format for Terraform schema
func ConvertConnectorsToMap(connectors json.RawMessage) []map[string]interface{} {
	// Handle empty or null connectors
	if len(connectors) == 0 || string(connectors) == "null" {
		return []map[string]interface{}{}
	}

	// Try to unmarshal as connector objects first
	var connectorArray []ConnectorSummary
	if err := json.Unmarshal(connectors, &connectorArray); err == nil {
		// Convert to map format with correct field names
		var result []map[string]interface{}
		for _, connector := range connectorArray {
			connectorMap := map[string]interface{}{
				"name":            connector.Name,
				"package":         connector.Package, // lowercase to match schema
				"state":           connector.State,
				"status":          connector.Status,
				"uuid_url":        connector.UUIDURL,
				"created_at":      connector.CreatedAt,
				"description":     connector.Description,
				"load_status":     connector.LoadStatus,
				"localization":    connector.Localization,
				"reach":           connector.Reach,
				"agent_infra_type": connector.AgentInfraType,
			}
			result = append(result, connectorMap)
		}
		return result
	}

	// If unmarshaling fails, return empty slice
	return []map[string]interface{}{}
}

// ConvertConnectorStrings handles simple string arrays (connector names or UUIDs)
func ConvertConnectorStrings(connectors json.RawMessage) []string {
	// Handle empty or null connectors
	if len(connectors) == 0 || string(connectors) == "null" {
		return []string{}
	}

	// Try to unmarshal as array of strings
	var stringArray []string
	if err := json.Unmarshal(connectors, &stringArray); err == nil {
		return stringArray // Direct return, no conversion needed
	}

	// If unmarshaling fails, return empty slice
	return []string{}
}





// ============================================================================
// VALIDATION UTILITIES
// ============================================================================

// ValidateRequiredString validates that a required string field is present and non-empty
func ValidateRequiredString(d *schema.ResourceData, fieldName string, ec *EaaClient) (string, error) {
	value, ok := d.GetOk(fieldName)
	if !ok {
		ec.Logger.Error(fmt.Sprintf("create ConnectorPool failed. '%s' is required but missing", fieldName))
		return "", fmt.Errorf("create ConnectorPool failed. '%s' is required but missing", fieldName)
	}

	valueStr, ok := value.(string)
	if !ok || valueStr == "" {
		ec.Logger.Error(fmt.Sprintf("create ConnectorPool failed. '%s' must be a non-empty string", fieldName))
		return "", fmt.Errorf("create ConnectorPool failed. '%s' must be a non-empty string", fieldName)
	}

	return valueStr, nil
}

// ValidateOptionalString validates that an optional string field is a string if present
func ValidateOptionalString(d *schema.ResourceData, fieldName string, ec *EaaClient) (string, error) {
	if value, ok := d.GetOk(fieldName); ok {
		valueStr, ok := value.(string)
		if !ok {
			ec.Logger.Error(fmt.Sprintf("%s must be a string", fieldName))
			return "", fmt.Errorf("%s must be a string, got %T", fieldName, value)
		}
		return valueStr, nil
	}
	return "", nil
}

// ValidateStringInSlice validates that a string value is in a given slice of valid values
func ValidateStringInSlice(val string, key string, validValues []string) (warns []string, errs []error) {
	found := false
	for _, validValue := range validValues {
		if val == validValue {
			found = true
			break
		}
	}

	if !found {
		errs = append(errs, fmt.Errorf("%s must be one of: %v", key, validValues))
	}

	return warns, errs
}

// ValidateTokenField validates a token field with type checking and range validation
func ValidateTokenField(value interface{}, fieldName string, min, max int, client *EaaClient) (int, error) {
	// Type checking
	intValue, ok := value.(int)
	if !ok {
		client.Logger.Error(fmt.Sprintf("%s must be an integer", fieldName))
		return 0, fmt.Errorf("%s must be an integer, got %T", fieldName, value)
	}
	
	// Range validation
	if intValue <= 0 || intValue > max {
		client.Logger.Error(fmt.Sprintf("%s must be in the range of 1 to %d", fieldName, max))
		return 0, fmt.Errorf("%s must be in the range of 1 to %d, got %d", fieldName, max, intValue)
	}
	
	return intValue, nil
}
