package client

import (
	"errors"
	"fmt"
	"os"
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

		// Include ALL fields, even if they have empty values
		// This ensures the complete configuration is visible in Terraform state
		if field.Kind() == reflect.Ptr {
			if field.IsNil() {
				// Include null pointers as null in the map
				advancedSettingsMap[tagName] = nil
			} else {
				// Dereference pointer fields
				advancedSettingsMap[tagName] = field.Elem().Interface()
			}
		} else {
			// Include all non-pointer fields, even if they're empty
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
	fmt.Fprintf(os.Stderr, "🔍 DEBUG: UpdateAdvancedSettings called\n")
	completeVal := reflect.ValueOf(complete).Elem()
	deltaVal := reflect.ValueOf(delta)
	for i := 0; i < deltaVal.NumField(); i++ {
		deltaField := deltaVal.Field(i)
		fieldName := deltaVal.Type().Field(i).Name
		completeField := completeVal.FieldByName(fieldName)

		if !deltaField.IsValid() || !completeField.IsValid() || !completeField.CanSet() {
			continue
		}

		// Always copy the field value, regardless of whether it's zero or not
		// This ensures ALL fields (including defaults) are included in the final payload
		if completeField.Kind() == reflect.String {
			// Handle string fields - convert pointer to string if needed
			if deltaField.Kind() == reflect.Ptr && !deltaField.IsNil() {
				completeField.SetString(deltaField.Elem().String())
			} else if deltaField.Kind() == reflect.String {
				completeField.SetString(deltaField.String())
			}
		} else if completeField.Kind() == reflect.Ptr {
			// Handle pointer fields - create pointer to the value
			if deltaField.Kind() == reflect.String {
				// Create a pointer to the string value
				strVal := deltaField.String()
				completeField.Set(reflect.ValueOf(&strVal))
			} else {
				// For other types, copy the pointer directly
				completeField.Set(deltaField)
			}
		} else if completeField.Kind() == reflect.Slice {
			completeField.Set(deltaField)
		} else if completeField.Kind() == reflect.Map {
			completeField.Set(deltaField)
		} else {
			// For other types (int, bool, etc.), copy directly
			completeField.Set(deltaField)
		}
	}
}
