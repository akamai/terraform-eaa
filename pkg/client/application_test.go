package client

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestProcessCustomDomainSkipsWhenHostMissing(t *testing.T) {
	resourceSchema := map[string]*schema.Schema{
		"cert_type": {
			Type:     schema.TypeString,
			Optional: true,
		},
	}

	d := schema.TestResourceDataRaw(t, resourceSchema, map[string]interface{}{})
	ec := &EaaClient{}
	appUpdateReq := &ApplicationUpdateRequest{}

	err := processCustomDomain(context.Background(), ec, appUpdateReq, d)
	if err != nil {
		t.Fatalf("expected nil error when host is missing, got %v", err)
	}
}
