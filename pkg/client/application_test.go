package client

import (
	"context"
	"testing"

	"github.com/hashicorp/go-hclog"
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
	ec := &EaaClient{Logger: hclog.NewNullLogger()}
	appUpdateReq := &ApplicationUpdateRequest{}

	err := processCustomDomain(ec, appUpdateReq, d, context.Background())
	if err != nil {
		t.Fatalf("expected nil error when host is missing, got %v", err)
	}
}
