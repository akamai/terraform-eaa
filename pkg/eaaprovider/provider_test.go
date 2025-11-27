package eaaprovider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var testAccProviders map[string]func() (*schema.Provider, error)

var testAccProvider *schema.Provider

func init() {
	testAccProvider = Provider()

	testAccProviders = map[string]func() (*schema.Provider, error){
		"eaa": func() (*schema.Provider, error) {
			return testAccProvider, nil
		},
	}
}

// Global mock transport instance to maintain state across requests
var globalMockTransport *MockHTTPTransport

// createMockedProvider creates a provider configured with a mocked client
func createMockedProvider() *schema.Provider {
	provider := Provider()

	// Don't reset global mock transport here - it's already set by UnitTestProviderFactories
	// This ensures state persists across multiple provider instances in the same test
	// The global transport is shared across all provider instances in a test

	// Override ConfigureContextFunc to return a mocked client
	provider.ConfigureContextFunc = func(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
		// createMockEaaClient uses the global transport, so state is shared
		mockClient := createMockEaaClient(globalMockTransport)
		return mockClient, nil
	}

	return provider
}
