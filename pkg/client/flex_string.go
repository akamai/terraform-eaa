package client

import (
	"encoding/json"
	"fmt"
)

// FlexString accepts both JSON strings and numbers, normalizing to a string.
type FlexString string

func (f *FlexString) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*f = FlexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(data, &n); err == nil {
		*f = FlexString(n.String())
		return nil
	}
	return fmt.Errorf("FlexString: cannot unmarshal %s: expected JSON string or number", string(data))
}
