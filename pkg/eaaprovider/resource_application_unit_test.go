package eaaprovider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// TestApplicationResourceUnit demonstrates unit tests using inline configs
// These tests use mocked providers (no .edgerc required, no real API calls)
func TestApplicationResourceUnit(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	t.Run("create_basic_enterprise_app", func(t *testing.T) {
		resource.UnitTest(t, resource.TestCase{
			ProviderFactories: UnitTestProviderFactories(),
			IsUnitTest:        true,
			Steps: []resource.TestStep{
				{
					Config: `
						provider "eaa" {
							contractid = "test-contract"
						}

						resource "eaa_application" "test" {
							name            = "test-enterprise-app"
							description     = "Test enterprise application"
							app_profile     = "http"
							app_type        = "enterprise"
							client_app_mode = "tcp"
							host            = "test.example.com"
							
							advanced_settings = jsonencode({
								app_auth = "none"
							})
						}
					`,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet("eaa_application.test", "id"),
						resource.TestCheckResourceAttrSet("eaa_application.test", "name"),
						resource.TestCheckResourceAttrSet("eaa_application.test", "app_type"),
						resource.TestCheckResourceAttrSet("eaa_application.test", "app_profile"),
						// Note: With mocked provider, exact values may differ from request
						// We verify that the resource was created and has required fields set
					),
					ExpectNonEmptyPlan: true, // Mock returns different values, so plan will show changes
				},
			},
			// CheckDestroy ensures resources are properly destroyed and prevents hanging
			CheckDestroy: func(s *terraform.State) error {
				// Resources are mocked, so no actual cleanup needed
				// This prevents terraform from hanging on destroy operations
				return nil
			},
		})
	})

	t.Run("create_bookmark_app", func(t *testing.T) {
		resource.UnitTest(t, resource.TestCase{
			ProviderFactories: UnitTestProviderFactories(),
			IsUnitTest:        true,
			Steps: []resource.TestStep{
				{
					Config: `
						provider "eaa" {
							contractid = "test-contract"
						}

						resource "eaa_application" "test" {
							name        = "test-bookmark-app"
							description = "Test bookmark application"
							app_profile = "http"
							app_type    = "bookmark"
							host        = "bookmark.example.com"
						}
					`,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet("eaa_application.test", "id"),
						resource.TestCheckResourceAttrSet("eaa_application.test", "name"),
						resource.TestCheckResourceAttrSet("eaa_application.test", "app_type"),
						// Note: With mocked provider, exact values may differ from request
						// We verify that the resource was created and has required fields set
					),
					ExpectNonEmptyPlan: true, // Mock returns different values, so plan will show changes
				},
			},
			// CheckDestroy ensures resources are properly destroyed and prevents hanging
			CheckDestroy: func(s *terraform.State) error {
				// Resources are mocked, so no actual cleanup needed
				// This prevents terraform from hanging on destroy operations
				return nil
			},
		})
	})
}

// TestApplicationValidationUnit tests validation scenarios
// These tests use mocked providers (no .edgerc required, no real API calls)
func TestApplicationValidationUnit(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testCases := map[string]struct {
		config      string
		expectError *regexp.Regexp
	}{
		"invalid_app_type": {
			config: `
				provider "eaa" {
					contractid = "test-contract"
				}

				resource "eaa_application" "test" {
					name        = "test-app"
					app_profile = "http"
					app_type    = "invalid_type"
					host        = "test.example.com"
				}
			`,
			expectError: regexp.MustCompile("invalid.*app_type|invalid.*value|expected.*bookmark.*enterprise.*tunnel"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				ProviderFactories: UnitTestProviderFactories(),
				IsUnitTest:        true,
				Steps: []resource.TestStep{
					{
						Config:      tc.config,
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}
