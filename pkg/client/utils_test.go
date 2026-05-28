package client

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDifferenceIgnoreCase(t *testing.T) {
	tests := map[string]struct {
		slice1 []string
		slice2 []string
		want   []string
	}{
		"no_difference": {
			slice1: []string{"a", "b"},
			slice2: []string{"a", "b"},
			want:   nil,
		},
		"all_different": {
			slice1: []string{"a", "b"},
			slice2: []string{"c", "d"},
			want:   []string{"a", "b"},
		},
		"case_insensitive": {
			slice1: []string{"Hello", "World"},
			slice2: []string{"hello", "WORLD"},
			want:   nil,
		},
		"partial_overlap": {
			slice1: []string{"a", "b", "c"},
			slice2: []string{"b"},
			want:   []string{"a", "c"},
		},
		"empty_first": {
			slice1: []string{},
			slice2: []string{"a"},
			want:   nil,
		},
		"empty_second": {
			slice1: []string{"a"},
			slice2: []string{},
			want:   []string{"a"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := DifferenceIgnoreCase(tt.slice1, tt.slice2)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConvertIntToEnumString(t *testing.T) {
	converter := func(i int) (string, error) {
		return AppTypeInt(i).String()
	}
	tests := map[string]struct {
		want  string
		input int
	}{
		"zero_returns_empty": {input: 0, want: ""},
		"valid_enterprise":   {input: int(APP_TYPE_ENTERPRISE_HOSTED), want: "enterprise"},
		"valid_saas":         {input: int(APP_TYPE_SAAS), want: "saas"},
		"invalid_fallback":   {input: 99, want: "99"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := ConvertIntToEnumString(tt.input, converter)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateStringInSlice(t *testing.T) {
	valid := []string{"a", "b", "c"}
	tests := map[string]struct {
		val     string
		wantErr bool
	}{
		"valid":   {val: "a", wantErr: false},
		"invalid": {val: "d", wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, errs := ValidateStringInSlice(tt.val, "test_key", valid)
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestConvertConnectorsToObjects(t *testing.T) {
	tests := map[string]struct {
		input json.RawMessage
		want  int // expected length
	}{
		"null":  {input: json.RawMessage("null"), want: 0},
		"empty": {input: json.RawMessage("[]"), want: 0},
		"valid": {
			input: json.RawMessage(`[{"name":"conn1","uuid_url":"uuid1"},{"name":"conn2","uuid_url":"uuid2"}]`),
			want:  2,
		},
		"invalid_json": {input: json.RawMessage(`{bad`), want: 0},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := ConvertConnectorsToObjects(tt.input)
			assert.Len(t, got, tt.want)
		})
	}
}

func TestConvertConnectorsToMap(t *testing.T) {
	tests := map[string]struct {
		input json.RawMessage
		want  int
	}{
		"null":  {input: json.RawMessage("null"), want: 0},
		"empty": {input: json.RawMessage("[]"), want: 0},
		"valid": {
			input: json.RawMessage(`[{"name":"conn1","uuid_url":"uuid1","package":1,"state":1,"status":1}]`),
			want:  1,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := ConvertConnectorsToMap(tt.input)
			assert.Len(t, got, tt.want)
		})
	}
}

func TestConvertConnectorStrings(t *testing.T) {
	tests := map[string]struct {
		input json.RawMessage
		want  []string
	}{
		"null":  {input: json.RawMessage("null"), want: []string{}},
		"empty": {input: json.RawMessage("[]"), want: []string{}},
		"valid": {
			input: json.RawMessage(`["a","b","c"]`),
			want:  []string{"a", "b", "c"},
		},
		"invalid": {input: json.RawMessage(`{bad`), want: []string{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := ConvertConnectorStrings(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateIntegerField(t *testing.T) {
	ec := newTestClient(t, jsonHandler(http.StatusOK, nil))

	tests := map[string]struct {
		value   interface{}
		min     int
		max     int
		want    int
		wantErr bool
	}{
		"valid":      {value: 5, min: 1, max: 10, want: 5},
		"at_min":     {value: 1, min: 1, max: 10, want: 1},
		"at_max":     {value: 10, min: 1, max: 10, want: 10},
		"below_min":  {value: 0, min: 1, max: 10, wantErr: true},
		"above_max":  {value: 11, min: 1, max: 10, wantErr: true},
		"wrong_type": {value: "not_int", min: 1, max: 10, wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := ValidateIntegerField(tt.value, "test_field", tt.min, tt.max, ec)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
