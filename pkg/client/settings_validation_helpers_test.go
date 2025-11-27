package client

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
)

func TestContains(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		item     string
		want     bool
	}{
		{
			name:     "item in slice",
			slice:    []string{"a", "b", "c"},
			item:     "b",
			want:     true,
		},
		{
			name:     "item not in slice",
			slice:    []string{"a", "b", "c"},
			item:     "d",
			want:     false,
		},
		{
			name:     "empty slice",
			slice:    []string{},
			item:     "a",
			want:     false,
		},
		{
			name:     "case sensitive",
			slice:    []string{"A", "B", "C"},
			item:     "a",
			want:     false,
		},
		{
			name:     "item matches first element",
			slice:    []string{"a", "b", "c"},
			item:     "a",
			want:     true,
		},
		{
			name:     "item matches last element",
			slice:    []string{"a", "b", "c"},
			item:     "c",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(tt.slice, tt.item)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestValidateStringSetting(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := []struct {
		name      string
		value     interface{}
		rule      SettingRule
		wantErr   bool
		errMsg    string
	}{
		{
			name:    "valid string with enum",
			value:   "on",
			rule:    SettingRule{Type: "string", ValidValues: []string{"on", "off"}},
			wantErr: false,
		},
		{
			name:    "invalid enum value",
			value:   "invalid",
			rule:    SettingRule{Type: "string", ValidValues: []string{"on", "off"}},
			wantErr: true,
			errMsg:  "must be one of",
		},
		{
			name:    "required empty string",
			value:   "",
			rule:    SettingRule{Type: "string", Required: true},
			wantErr: true,
			errMsg:  "required setting cannot be empty",
		},
		{
			name:    "optional empty string",
			value:   "",
			rule:    SettingRule{Type: "string", Required: false},
			wantErr: false,
		},
		{
			name:    "wrong type",
			value:   123,
			rule:    SettingRule{Type: "string"},
			wantErr: true,
			errMsg:  "expected string",
		},
		{
			name:    "nil value",
			value:   nil,
			rule:    SettingRule{Type: "string"},
			wantErr: true,
			errMsg:  "expected string",
		},
		{
			name:    "valid enum value at beginning",
			value:   "on",
			rule:    SettingRule{Type: "string", ValidValues: []string{"on", "off"}},
			wantErr: false,
		},
		{
			name:    "valid enum value at end",
			value:   "off",
			rule:    SettingRule{Type: "string", ValidValues: []string{"on", "off"}},
			wantErr: false,
		},
		{
			name:    "enum case sensitive",
			value:   "ON",
			rule:    SettingRule{Type: "string", ValidValues: []string{"on", "off"}},
			wantErr: true,
			errMsg:  "must be one of",
		},
		{
			name:    "single valid value",
			value:   "only",
			rule:    SettingRule{Type: "string", ValidValues: []string{"only"}},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateStringSetting(tt.value, tt.rule, logger)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateIntSetting(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := []struct {
		name      string
		value     interface{}
		rule      SettingRule
		wantErr   bool
		errMsg    string
	}{
		{
			name:    "valid int in range",
			value:   50,
			rule:    SettingRule{Type: "int", MinValue: 1, MaxValue: 100},
			wantErr: false,
		},
		{
			name:    "valid int at minimum",
			value:   1,
			rule:    SettingRule{Type: "int", MinValue: 1, MaxValue: 100},
			wantErr: false,
		},
		{
			name:    "valid int at maximum",
			value:   100,
			rule:    SettingRule{Type: "int", MinValue: 1, MaxValue: 100},
			wantErr: false,
		},
		{
			name:    "int below minimum",
			value:   0,
			rule:    SettingRule{Type: "int", MinValue: 1, MaxValue: 100},
			wantErr: true,
			errMsg:  "must be between",
		},
		{
			name:    "int above maximum",
			value:   101,
			rule:    SettingRule{Type: "int", MinValue: 1, MaxValue: 100},
			wantErr: true,
			errMsg:  "must be between",
		},
		{
			name:    "float64 value",
			value:   50.0,
			rule:    SettingRule{Type: "int", MinValue: 1, MaxValue: 100},
			wantErr: false,
		},
		{
			name:    "string parsed as int",
			value:   "50",
			rule:    SettingRule{Type: "int", MinValue: 1, MaxValue: 100},
			wantErr: false, // validateIntSetting can parse string to int
		},
		{
			name:    "invalid string for int",
			value:   "not-a-number",
			rule:    SettingRule{Type: "int", MinValue: 1, MaxValue: 100},
			wantErr: true,
			errMsg:  "expected integer",
		},
		{
			name:    "string int below minimum",
			value:   "0",
			rule:    SettingRule{Type: "int", MinValue: 1, MaxValue: 100},
			wantErr: true,
			errMsg:  "must be between",
		},
		{
			name:    "string int above maximum",
			value:   "101",
			rule:    SettingRule{Type: "int", MinValue: 1, MaxValue: 100},
			wantErr: true,
			errMsg:  "must be between",
		},
		{
			name:    "TLS suite type default",
			value:   "default",
			rule:    SettingRule{Type: "int", ValidValues: []string{"default"}},
			wantErr: false,
		},
		{
			name:    "TLS suite type custom",
			value:   "custom",
			rule:    SettingRule{Type: "int", ValidValues: []string{"default"}},
			wantErr: true, // Only "default" is in ValidValues
		},
		{
			name:    "nil value",
			value:   nil,
			rule:    SettingRule{Type: "int", MinValue: 1, MaxValue: 100},
			wantErr: true,
			errMsg:  "expected integer",
		},
		{
			name:    "bool value",
			value:   true,
			rule:    SettingRule{Type: "int", MinValue: 1, MaxValue: 100},
			wantErr: true,
			errMsg:  "expected integer",
		},
		{
			name:    "float32 value",
			value:   float32(50.0),
			rule:    SettingRule{Type: "int", MinValue: 1, MaxValue: 100},
			wantErr: true, // Only float64 is supported
			errMsg:  "expected integer",
		},
		{
			name:    "int with enum values",
			value:   1,
			rule:    SettingRule{Type: "int", ValidValues: []string{"1", "2", "3"}},
			wantErr: false,
		},
		{
			name:    "int with enum values mismatch",
			value:   4,
			rule:    SettingRule{Type: "int", ValidValues: []string{"1", "2", "3"}},
			wantErr: true,
			errMsg:  "must be one of",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIntSetting(tt.value, tt.rule, logger)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateSettingDependencies(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := []struct {
		name      string
		settingName string
		rule      SettingRule
		settings  map[string]interface{}
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "dependency satisfied",
			settingName: "dependent_field",
			rule: SettingRule{
				DependsOn: map[string]string{"required_field": "value"},
			},
			settings: map[string]interface{}{
				"required_field": "value",
			},
			wantErr: false,
		},
		{
			name:      "dependency missing",
			settingName: "dependent_field",
			rule: SettingRule{
				DependsOn: map[string]string{"required_field": "value"},
			},
			settings: map[string]interface{}{},
			wantErr: true,
			errMsg:  "field 'required_field' is required",
		},
		{
			name:      "dependency wrong value",
			settingName: "dependent_field",
			rule: SettingRule{
				DependsOn: map[string]string{"required_field": "value"},
			},
			settings: map[string]interface{}{
				"required_field": "wrong_value",
			},
			wantErr: true,
			errMsg:  "must have value",
		},
		{
			name:      "no dependencies",
			settingName: "independent_field",
			rule: SettingRule{
				DependsOn: nil,
			},
			settings: map[string]interface{}{},
			wantErr: false,
		},
		{
			name:      "multiple dependencies",
			settingName: "dependent_field",
			rule: SettingRule{
				DependsOn: map[string]string{
					"field1": "value1",
					"field2": "value2",
				},
			},
			settings: map[string]interface{}{
				"field1": "value1",
				"field2": "value2",
			},
			wantErr: false,
		},
		{
			name:      "multiple dependencies one missing",
			settingName: "dependent_field",
			rule: SettingRule{
				DependsOn: map[string]string{
					"field1": "value1",
					"field2": "value2",
				},
			},
			settings: map[string]interface{}{
				"field1": "value1",
				// field2 missing
			},
			wantErr: true,
			errMsg:  "field 'field2' is required",
		},
		{
			name:      "multiple dependencies one wrong value",
			settingName: "dependent_field",
			rule: SettingRule{
				DependsOn: map[string]string{
					"field1": "value1",
					"field2": "value2",
				},
			},
			settings: map[string]interface{}{
				"field1": "value1",
				"field2": "wrong_value",
			},
			wantErr: true,
			errMsg:  "must have value",
		},
		{
			name:      "dependency with OR logic",
			settingName: "dependent_field",
			rule: SettingRule{
				DependsOn: map[string]string{
					"field1": "value1|value2",
				},
			},
			settings: map[string]interface{}{
				"field1": "value1",
			},
			wantErr: false,
		},
		{
			name:      "dependency with OR logic second value",
			settingName: "dependent_field",
			rule: SettingRule{
				DependsOn: map[string]string{
					"field1": "value1|value2",
				},
			},
			settings: map[string]interface{}{
				"field1": "value2",
			},
			wantErr: false,
		},
		{
			name:      "dependency with OR logic no match",
			settingName: "dependent_field",
			rule: SettingRule{
				DependsOn: map[string]string{
					"field1": "value1|value2",
				},
			},
			settings: map[string]interface{}{
				"field1": "value3",
			},
			wantErr: true,
			errMsg:  "must have value",
		},
		{
			name:      "dependency with int value",
			settingName: "dependent_field",
			rule: SettingRule{
				DependsOn: map[string]string{
					"field1": "123",
				},
			},
			settings: map[string]interface{}{
				"field1": 123,
			},
			wantErr: false,
		},
		{
			name:      "dependency with bool value",
			settingName: "dependent_field",
			rule: SettingRule{
				DependsOn: map[string]string{
					"field1": "true",
				},
			},
			settings: map[string]interface{}{
				"field1": true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSettingDependencies(tt.settingName, tt.rule, tt.settings, logger)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateSettingValue(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := []struct {
		name      string
		value     interface{}
		rule      SettingRule
		wantErr   bool
		errMsg    string
	}{
		{
			name:    "valid string enum",
			value:   "on",
			rule:    SettingRule{Type: "string", ValidValues: []string{"on", "off"}},
			wantErr: false,
		},
		{
			name:    "string from int conversion",
			value:   1,
			rule:    SettingRule{Type: "string", ValidValues: []string{"1", "2"}},
			wantErr: false,
		},
		{
			name:    "string from float conversion",
			value:   50.0,
			rule:    SettingRule{Type: "string"},
			wantErr: false,
		},
		{
			name:    "required empty string",
			value:   "",
			rule:    SettingRule{Type: "string", Required: true},
			wantErr: true,
			errMsg:  "required setting cannot be empty",
		},
		{
			name:    "invalid enum value",
			value:   "invalid",
			rule:    SettingRule{Type: "string", ValidValues: []string{"on", "off"}},
			wantErr: true,
			errMsg:  "must be one of",
		},
		{
			name:    "unsupported type",
			value:   []string{"test"},
			rule:    SettingRule{Type: "string"},
			wantErr: true,
			errMsg:  "expected string-compatible type",
		},
		{
			name:    "valid int setting",
			value:   50,
			rule:    SettingRule{Type: "int", MinValue: 1, MaxValue: 100},
			wantErr: false,
		},
		{
			name:    "valid array setting",
			value:   []interface{}{"item1", "item2"},
			rule:    SettingRule{Type: "array"},
			wantErr: false,
		},
		{
			name:    "nil value for optional setting",
			value:   nil,
			rule:    SettingRule{Type: "string", Required: false},
			wantErr: false,
		},
		{
			name:    "nil value for required setting",
			value:   nil,
			rule:    SettingRule{Type: "string", Required: true},
			wantErr: true,
			errMsg:  "required setting cannot be null",
		},
		{
			name:    "unsupported setting type",
			value:   "value",
			rule:    SettingRule{Type: "unsupported"},
			wantErr: true,
			errMsg:  "unsupported setting type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSettingValue(tt.value, tt.rule, logger)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateDependencyValue(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := []struct {
		name          string
		fieldValue    interface{}
		requiredValue string
		want          bool
	}{
		{
			name:          "exact string match",
			fieldValue:    "value",
			requiredValue: "value",
			want:          true,
		},
		{
			name:          "string mismatch",
			fieldValue:    "value",
			requiredValue: "other",
			want:          false,
		},
		{
			name:          "OR logic match first",
			fieldValue:    "value1",
			requiredValue: "value1|value2",
			want:          true,
		},
		{
			name:          "OR logic match second",
			fieldValue:    "value2",
			requiredValue: "value1|value2",
			want:          true,
		},
		{
			name:          "OR logic no match",
			fieldValue:    "value3",
			requiredValue: "value1|value2",
			want:          false,
		},
		{
			name:          "int to string conversion match",
			fieldValue:    123,
			requiredValue: "123",
			want:          true,
		},
		{
			name:          "int to string conversion mismatch",
			fieldValue:    123,
			requiredValue: "456",
			want:          false,
		},
		{
			name:          "bool true to string",
			fieldValue:    true,
			requiredValue: "true",
			want:          true,
		},
		{
			name:          "bool false to string",
			fieldValue:    false,
			requiredValue: "false",
			want:          true,
		},
		{
			name:          "bool true mismatch",
			fieldValue:    true,
			requiredValue: "false",
			want:          false,
		},
		{
			name:          "OR logic with spaces",
			fieldValue:    "value1",
			requiredValue: "value1 | value2",
			want:          true,
		},
		{
			name:          "OR logic with multiple spaces",
			fieldValue:    "value2",
			requiredValue: "value1 | value2 | value3",
			want:          true,
		},
		{
			name:          "OR logic no match with spaces",
			fieldValue:    "value4",
			requiredValue: "value1 | value2 | value3",
			want:          false,
		},
		{
			name:          "unsupported type returns false",
			fieldValue:    []string{"test"},
			requiredValue: "test",
			want:          false,
		},
		{
			name:          "float64 value",
			fieldValue:    123.45,
			requiredValue: "123.45",
			want:          false, // Float64 not supported, returns false
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateDependencyValue(tt.fieldValue, tt.requiredValue, logger)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestValidateAdvancedSettingsAPIDependent(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := []struct {
		name      string
		settings  map[string]interface{}
		m         interface{}
		wantErr   bool
	}{
		{
			name:      "no tlsSuiteType",
			settings:  map[string]interface{}{"other_setting": "value"},
			m:         nil,
			wantErr:   false,
		},
		{
			name:      "tlsSuiteType not CUSTOM",
			settings:  map[string]interface{}{"tlsSuiteType": 1},
			m:         nil,
			wantErr:   false,
		},
		{
			name:      "tlsSuiteType is CUSTOM (2)",
			settings:  map[string]interface{}{"tlsSuiteType": 2},
			m:         nil,
			wantErr:   false, // Validation handled at provider level
		},
		{
			name:      "tlsSuiteType not int",
			settings:  map[string]interface{}{"tlsSuiteType": "2"},
			m:         nil,
			wantErr:   false,
		},
		{
			name:      "empty settings",
			settings:  map[string]interface{}{},
			m:         nil,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAdvancedSettingsAPIDependent(tt.settings, tt.m, logger)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateFieldConflicts(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := []struct {
		name      string
		settings  map[string]interface{}
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "no conflicts",
			settings:  map[string]interface{}{"setting1": "value1", "setting2": "value2"},
			wantErr:   false,
		},
		{
			name:      "empty settings",
			settings:  map[string]interface{}{},
			wantErr:   false,
		},
		{
			name:      "multiple settings no conflicts",
			settings:  map[string]interface{}{
				"acceleration": "on",
				"allow_cors": "true",
				"logging_enabled": "true",
			},
			wantErr: false,
		},
		{
			name:      "unknown field ignored",
			settings:  map[string]interface{}{
				"unknown_field": "value",
			},
			wantErr: false,
		},
		{
			name:      "field with no conditional rules",
			settings:  map[string]interface{}{
				"some_setting": "value",
			},
			wantErr: false,
		},
		{
			name:      "conditional field not present",
			settings:  map[string]interface{}{
				"setting1": "value1",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFieldConflicts(tt.settings, logger)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateHealthCheckRequiredDependencies(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := []struct {
		name     string
		settings map[string]interface{}
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "no health check type",
			settings: map[string]interface{}{},
			wantErr:  false,
		},
		{
			name: "health check type not HTTP/HTTPS",
			settings: map[string]interface{}{
				"health_check_type": "tcp",
			},
			wantErr: false,
		},
		{
			name: "HTTP health check with all required fields",
			settings: map[string]interface{}{
				"health_check_type":        "HTTP",
				"health_check_http_url":    "/health",
				"health_check_http_version": "HTTP/1.1",
				"health_check_http_host_header": "example.com",
			},
			wantErr: false,
		},
		{
			name: "HTTPS health check with all required fields",
			settings: map[string]interface{}{
				"health_check_type":        "HTTPS",
				"health_check_http_url":    "/health",
				"health_check_http_version": "HTTP/1.1",
				"health_check_http_host_header": "example.com",
			},
			wantErr: false,
		},
		{
			name: "HTTP health check missing url",
			settings: map[string]interface{}{
				"health_check_type":        "HTTP",
				"health_check_http_version": "HTTP/1.1",
				"health_check_http_host_header": "example.com",
			},
			wantErr: true,
			errMsg:  "health_check_http_url is required",
		},
		{
			name: "HTTP health check missing version",
			settings: map[string]interface{}{
				"health_check_type":        "HTTP",
				"health_check_http_url":    "/health",
				"health_check_http_host_header": "example.com",
			},
			wantErr: true,
			errMsg:  "health_check_http_version is required",
		},
		{
			name: "HTTP health check missing host header",
			settings: map[string]interface{}{
				"health_check_type":        "HTTP",
				"health_check_http_url":    "/health",
				"health_check_http_version": "HTTP/1.1",
			},
			wantErr: true,
			errMsg:  "health_check_http_host_header is required",
		},
		{
			name: "HTTP health check empty url",
			settings: map[string]interface{}{
				"health_check_type":        "HTTP",
				"health_check_http_url":    "",
				"health_check_http_version": "HTTP/1.1",
				"health_check_http_host_header": "example.com",
			},
			wantErr: true,
			errMsg:  "health_check_http_url is required",
		},
		{
			name: "HTTP health check empty version",
			settings: map[string]interface{}{
				"health_check_type":        "HTTP",
				"health_check_http_url":    "/health",
				"health_check_http_version": "",
				"health_check_http_host_header": "example.com",
			},
			wantErr: true,
			errMsg:  "health_check_http_version is required",
		},
		{
			name: "HTTP health check empty host header allowed",
			settings: map[string]interface{}{
				"health_check_type":        "HTTP",
				"health_check_http_url":    "/health",
				"health_check_http_version": "HTTP/1.1",
				"health_check_http_host_header": "",
			},
			wantErr: false, // Empty host header is allowed
		},
		{
			name: "health check type invalid type",
			settings: map[string]interface{}{
				"health_check_type": 123,
			},
			wantErr: false, // Invalid type will be caught by other validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHealthCheckRequiredDependencies(tt.settings, logger)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" && err != nil {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

