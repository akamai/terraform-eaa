// pkg/client/appservices_test.go
package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestACLSetting_Validate(t *testing.T) {
	tests := map[string]struct {
		setting ACLSetting
		wantErr bool
	}{
		"valid_is": {
			setting: ACLSetting{Operator: "==", Type: "url", Value: "/test"},
		},
		"valid_is_not": {
			setting: ACLSetting{Operator: "!=", Type: "country", Value: "US"},
		},
		"invalid_operator": {
			setting: ACLSetting{Operator: ">", Type: "url", Value: "/test"},
			wantErr: true,
		},
		"invalid_type": {
			setting: ACLSetting{Operator: "==", Type: "invalid", Value: "/test"},
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := tt.setting.Validate()
			requireErr(t, err, tt.wantErr)
		})
	}
}

func TestAccessRule_IsEqual(t *testing.T) {
	rule1 := AccessRule{
		Name:   "rule-1",
		Status: 1,
		Settings: []ACLSetting{
			{Operator: "==", Type: "url", Value: "/test"},
		},
	}
	rule2 := AccessRule{
		Name:   "rule-1",
		Status: 1,
		Settings: []ACLSetting{
			{Operator: "==", Type: "url", Value: "/test"},
		},
	}
	rule3 := AccessRule{
		Name:   "rule-different",
		Status: 0,
		Settings: []ACLSetting{
			{Operator: "!=", Type: "country", Value: "US"},
		},
	}

	tests := map[string]struct {
		a    AccessRule
		b    AccessRule
		want bool
	}{
		"equal":            {a: rule1, b: rule2, want: true},
		"different_status": {a: rule1, b: rule3, want: false},
		"different_settings_count": {
			a:    rule1,
			b:    AccessRule{Status: 1, Settings: []ACLSetting{}},
			want: false,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.a.IsEqual(tt.b))
		})
	}
}
