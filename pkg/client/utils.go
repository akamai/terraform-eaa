package client

import (
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

		// Check if the field is set and is of type string or *string
		if deltaField.IsValid() && completeField.IsValid() && completeField.CanSet() &&
			(completeField.Kind() == reflect.String || completeField.Kind() == reflect.Ptr) {
			if deltaField.Kind() == reflect.Ptr && !deltaField.IsNil() {
				completeField.Set(deltaField)
			} else if deltaField.Kind() == reflect.String {
				completeField.Set(deltaField)
			}
		}
	}
}
