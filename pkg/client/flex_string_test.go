package client

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlexString_UnmarshalJSON_String(t *testing.T) {
	var f FlexString
	err := json.Unmarshal([]byte(`"20"`), &f)
	require.NoError(t, err)
	assert.Equal(t, FlexString("20"), f)
}

func TestFlexString_UnmarshalJSON_Integer(t *testing.T) {
	var f FlexString
	err := json.Unmarshal([]byte(`20`), &f)
	require.NoError(t, err)
	assert.Equal(t, FlexString("20"), f)
}

func TestFlexString_UnmarshalJSON_Float(t *testing.T) {
	var f FlexString
	err := json.Unmarshal([]byte(`20.5`), &f)
	require.NoError(t, err)
	assert.Equal(t, FlexString("20.5"), f)
}

func TestFlexString_MarshalJSON(t *testing.T) {
	f := FlexString("20")
	data, err := json.Marshal(f)
	require.NoError(t, err)
	assert.Equal(t, `"20"`, string(data))
}

func TestFlexString_RoundTripInStruct(t *testing.T) {
	type example struct {
		Value FlexString `json:"value"`
	}

	// Unmarshal from number
	var s1 example
	err := json.Unmarshal([]byte(`{"value": 42}`), &s1)
	require.NoError(t, err)
	assert.Equal(t, FlexString("42"), s1.Value)

	// Marshal back to string
	data, err := json.Marshal(s1)
	require.NoError(t, err)
	assert.JSONEq(t, `{"value":"42"}`, string(data))

	// Unmarshal from string
	var s2 example
	err = json.Unmarshal([]byte(`{"value": "42"}`), &s2)
	require.NoError(t, err)
	assert.Equal(t, FlexString("42"), s2.Value)
}

func TestFlexString_UnmarshalJSON_Null(t *testing.T) {
	var f FlexString
	err := json.Unmarshal([]byte(`null`), &f)
	require.NoError(t, err)
	assert.Equal(t, FlexString(""), f)
}

func TestFlexString_UnmarshalJSON_NullInStruct(t *testing.T) {
	type example struct {
		Value FlexString `json:"value"`
	}
	var s example
	err := json.Unmarshal([]byte(`{"value": null}`), &s)
	require.NoError(t, err)
	assert.Equal(t, FlexString(""), s.Value)
}

func TestFlexString_UnmarshalJSON_Boolean(t *testing.T) {
	var f FlexString
	err := json.Unmarshal([]byte(`true`), &f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "FlexString: cannot unmarshal")
}

func TestFlexString_UnmarshalJSON_InvalidInput(t *testing.T) {
	var f FlexString
	err := json.Unmarshal([]byte(`[1,2,3]`), &f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "FlexString: cannot unmarshal")
}

func TestFlexString_UnmarshalJSON_EmptyString(t *testing.T) {
	var f FlexString
	err := json.Unmarshal([]byte(`""`), &f)
	require.NoError(t, err)
	assert.Equal(t, FlexString(""), f)
}

func TestFlexString_OmitemptyBehavior(t *testing.T) {
	type example struct {
		Value FlexString `json:"value,omitempty"`
	}

	t.Run("zero_value_not_dropped", func(t *testing.T) {
		e := example{Value: FlexString("0")}
		data, err := json.Marshal(e)
		require.NoError(t, err)
		assert.Contains(t, string(data), `"value"`)
	})

	t.Run("negative_value_not_dropped", func(t *testing.T) {
		var f FlexString
		err := json.Unmarshal([]byte(`-1`), &f)
		require.NoError(t, err)
		assert.Equal(t, FlexString("-1"), f)
	})

	t.Run("empty_string_dropped", func(t *testing.T) {
		e := example{Value: FlexString("")}
		data, err := json.Marshal(e)
		require.NoError(t, err)
		assert.NotContains(t, string(data), `"value"`)
	})
}
