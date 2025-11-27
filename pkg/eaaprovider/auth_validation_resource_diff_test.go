package eaaprovider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestValidateWSFEDNestedBlocks tests ValidateWSFEDNestedBlocks using terraform-plugin-testing
// These tests use PlanOnly: true to create proper *schema.ResourceDiff instances
func TestValidateWSFEDNestedBlocks(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	tests := map[string]struct {
		config      string
		expectError bool
		errorText   string
	}{
		"wsfed_enabled_with_valid_idp": {
			config: `
				provider "eaa" {
					contractid = "test-contract"
				}

				resource "eaa_application" "test" {
					name            = "test-wsfed-app"
					app_type        = "enterprise"
					app_profile     = "http"
					client_app_mode = "tcp"
					host            = "test.example.com"
					
					wsfed_settings {
						idp {
							self_signed = true
						}
					}
					
					advanced_settings = jsonencode({
						app_auth = "wsfed"
					})
				}
			`,
			expectError: false,
		},
		"wsfed_enabled_without_sign_cert": {
			config: `
				provider "eaa" {
					contractid = "test-contract"
				}

				resource "eaa_application" "test" {
					name            = "test-wsfed-app"
					app_type        = "enterprise"
					app_profile     = "http"
					client_app_mode = "tcp"
					host            = "test.example.com"
					
					wsfed_settings {
						idp {
							self_signed = false
							# sign_cert missing - should fail validation
						}
					}
					
					advanced_settings = jsonencode({
						app_auth = "wsfed"
					})
				}
			`,
			expectError: true,
			errorText:   "sign_cert",
		},
		"wsfed_enabled_with_sign_cert": {
			config: `
				provider "eaa" {
					contractid = "test-contract"
				}

				resource "eaa_application" "test" {
					name            = "test-wsfed-app"
					app_type        = "enterprise"
					app_profile     = "http"
					client_app_mode = "tcp"
					host            = "test.example.com"
					
					wsfed_settings {
						idp {
							self_signed = false
							sign_cert   = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
						}
					}
					
					advanced_settings = jsonencode({
						app_auth = "wsfed"
					})
				}
			`,
			expectError: false,
		},
		"wsfed_not_enabled": {
			config: `
				provider "eaa" {
					contractid = "test-contract"
				}

				resource "eaa_application" "test" {
					name            = "test-app"
					app_type        = "enterprise"
					app_profile     = "http"
					client_app_mode = "tcp"
					host            = "test.example.com"
					
					advanced_settings = jsonencode({
						app_auth = "none"
					})
				}
			`,
			expectError: false, // Should skip validation when wsfed not enabled
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			testStep := resource.TestStep{
				Config: tt.config,
			}

			if tt.expectError {
				if tt.errorText != "" {
					testStep.ExpectError = regexp.MustCompile(tt.errorText)
				} else {
					testStep.ExpectError = regexp.MustCompile(".*") // Match any error
				}
			} else {
				// For success cases, we just verify the plan can be created
				// The validation happens during CustomizeDiff which runs during plan
				testStep.PlanOnly = true
				testStep.ExpectNonEmptyPlan = true // We expect a plan (resource creation)
			}

			resource.UnitTest(t, resource.TestCase{
				ProviderFactories: UnitTestProviderFactories(),
				IsUnitTest:        true,
				Steps:             []resource.TestStep{testStep},
			})
		})
	}
}

// TestValidateSAMLNestedBlocks tests ValidateSAMLNestedBlocks using terraform-plugin-testing
// These tests use PlanOnly: true to create proper *schema.ResourceDiff instances
func TestValidateSAMLNestedBlocks(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	tests := map[string]struct {
		config      string
		expectError bool
		errorText   string
	}{
		"saml_enabled_with_valid_idp": {
			config: `
				provider "eaa" {
					contractid = "test-contract"
				}

				resource "eaa_application" "test" {
					name            = "test-saml-app"
					app_type        = "enterprise"
					app_profile     = "http"
					client_app_mode = "tcp"
					host            = "test.example.com"
					
					saml_settings {
						idp {
							self_signed = true
						}
					}
					
					advanced_settings = jsonencode({
						app_auth = "saml"
					})
				}
			`,
			expectError: false,
		},
		"saml_enabled_without_sign_cert": {
			config: `
				provider "eaa" {
					contractid = "test-contract"
				}

				resource "eaa_application" "test" {
					name            = "test-saml-app"
					app_type        = "enterprise"
					app_profile     = "http"
					client_app_mode = "tcp"
					host            = "test.example.com"
					
					saml_settings {
						idp {
							self_signed = false
							# sign_cert missing - should fail validation
						}
					}
					
					advanced_settings = jsonencode({
						app_auth = "saml"
					})
				}
			`,
			expectError: true,
			errorText:   "sign_cert",
		},
		"saml_enabled_with_sign_cert": {
			config: `
				provider "eaa" {
					contractid = "test-contract"
				}

				resource "eaa_application" "test" {
					name            = "test-saml-app"
					app_type        = "enterprise"
					app_profile     = "http"
					client_app_mode = "tcp"
					host            = "test.example.com"
					
					saml_settings {
						idp {
							self_signed = false
							sign_cert   = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
						}
					}
					
					advanced_settings = jsonencode({
						app_auth = "saml"
					})
				}
			`,
			expectError: false,
		},
		"saml_enabled_with_duplicate_attrmap": {
			config: `
				provider "eaa" {
					contractid = "test-contract"
				}

				resource "eaa_application" "test" {
					name            = "test-saml-app"
					app_type        = "enterprise"
					app_profile     = "http"
					client_app_mode = "tcp"
					host            = "test.example.com"
					
					saml_settings {
						idp {
							self_signed = true
						}
						
						attrmap {
							name = "email"
							src  = "user.email"
						}
						
						attrmap {
							name = "email"  # Duplicate - should fail validation
							src  = "user.email"
						}
					}
					
					advanced_settings = jsonencode({
						app_auth = "saml"
					})
				}
			`,
			expectError: true,
			errorText:   "duplicate attribute name",
		},
		"saml_enabled_with_valid_attrmap": {
			config: `
				provider "eaa" {
					contractid = "test-contract"
				}

				resource "eaa_application" "test" {
					name            = "test-saml-app"
					app_type        = "enterprise"
					app_profile     = "http"
					client_app_mode = "tcp"
					host            = "test.example.com"
					
					saml_settings {
						idp {
							self_signed = true
						}
						
						attrmap {
							name = "email"
							src  = "user.email"
						}
						
						attrmap {
							name = "name"
							src  = "user.name"
						}
					}
					
					advanced_settings = jsonencode({
						app_auth = "saml"
					})
				}
			`,
			expectError: false,
		},
		"saml_not_enabled": {
			config: `
				provider "eaa" {
					contractid = "test-contract"
				}

				resource "eaa_application" "test" {
					name            = "test-app"
					app_type        = "enterprise"
					app_profile     = "http"
					client_app_mode = "tcp"
					host            = "test.example.com"
					
					advanced_settings = jsonencode({
						app_auth = "none"
					})
				}
			`,
			expectError: false, // Should skip validation when saml not enabled
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			testStep := resource.TestStep{
				Config: tt.config,
			}

			if tt.expectError {
				if tt.errorText != "" {
					testStep.ExpectError = regexp.MustCompile(tt.errorText)
				} else {
					testStep.ExpectError = regexp.MustCompile(".*") // Match any error
				}
			} else {
				// For success cases, we just verify the plan can be created
				// The validation happens during CustomizeDiff which runs during plan
				testStep.PlanOnly = true
				testStep.ExpectNonEmptyPlan = true // We expect a plan (resource creation)
			}

			resource.UnitTest(t, resource.TestCase{
				ProviderFactories: UnitTestProviderFactories(),
				IsUnitTest:        true,
				Steps:             []resource.TestStep{testStep},
			})
		})
	}
}

// TestValidateOIDCNestedBlocks tests ValidateOIDCNestedBlocks using terraform-plugin-testing
// These tests use PlanOnly: true to create proper *schema.ResourceDiff instances
func TestValidateOIDCNestedBlocks(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	tests := map[string]struct {
		config      string
		expectError bool
		errorText   string
	}{
		"oidc_enabled_with_valid_clients": {
			config: `
				provider "eaa" {
					contractid = "test-contract"
				}

				resource "eaa_application" "test" {
					name            = "test-oidc-app"
					app_type        = "enterprise"
					app_profile     = "http"
					client_app_mode = "tcp"
					host            = "test.example.com"
					
					oidc_settings {
						oidc_clients {
							response_type = ["code"]
							redirect_uris  = ["https://example.com/callback"]
						}
					}
					
					advanced_settings = jsonencode({
						app_auth = "oidc"
					})
				}
			`,
			expectError: false,
		},
		"oidc_enabled_with_invalid_client": {
			config: `
				provider "eaa" {
					contractid = "test-contract"
				}

				resource "eaa_application" "test" {
					name            = "test-oidc-app"
					app_type        = "enterprise"
					app_profile     = "http"
					client_app_mode = "tcp"
					host            = "test.example.com"
					
					oidc_settings {
						oidc_clients {
							response_type = "not-an-array"  # Invalid - should fail validation
							redirect_uris  = ["https://example.com/callback"]
						}
					}
					
					advanced_settings = jsonencode({
						app_auth = "oidc"
					})
				}
			`,
			expectError: true,
		},
		"oidc_enabled_with_invalid_redirect_uris": {
			config: `
				provider "eaa" {
					contractid = "test-contract"
				}

				resource "eaa_application" "test" {
					name            = "test-oidc-app"
					app_type        = "enterprise"
					app_profile     = "http"
					client_app_mode = "tcp"
					host            = "test.example.com"
					
					oidc_settings {
						oidc_clients {
							response_type = ["code"]
							redirect_uris  = "not-an-array"  # Invalid - should fail validation
						}
					}
					
					advanced_settings = jsonencode({
						app_auth = "oidc"
					})
				}
			`,
			expectError: true,
		},
		"oidc_enabled_with_invalid_javascript_origins": {
			config: `
				provider "eaa" {
					contractid = "test-contract"
				}

				resource "eaa_application" "test" {
					name            = "test-oidc-app"
					app_type        = "enterprise"
					app_profile     = "http"
					client_app_mode = "tcp"
					host            = "test.example.com"
					
					oidc_settings {
						oidc_clients {
							response_type     = ["code"]
							redirect_uris     = ["https://example.com/callback"]
							javascript_origins = "not-an-array"  # Invalid - should fail validation
						}
					}
					
					advanced_settings = jsonencode({
						app_auth = "oidc"
					})
				}
			`,
			expectError: true,
		},
		"oidc_enabled_with_invalid_post_logout_redirect_uri": {
			config: `
				provider "eaa" {
					contractid = "test-contract"
				}

				resource "eaa_application" "test" {
					name            = "test-oidc-app"
					app_type        = "enterprise"
					app_profile     = "http"
					client_app_mode = "tcp"
					host            = "test.example.com"
					
					oidc_settings {
						oidc_clients {
							response_type            = ["code"]
							redirect_uris            = ["https://example.com/callback"]
							post_logout_redirect_uri = "not-an-array"  # Invalid - should fail validation
						}
					}
					
					advanced_settings = jsonencode({
						app_auth = "oidc"
					})
				}
			`,
			expectError: true,
		},
		"oidc_enabled_with_invalid_claims_not_array": {
			config: `
				provider "eaa" {
					contractid = "test-contract"
				}

				resource "eaa_application" "test" {
					name            = "test-oidc-app"
					app_type        = "enterprise"
					app_profile     = "http"
					client_app_mode = "tcp"
					host            = "test.example.com"
					
					oidc_settings {
						oidc_clients {
							response_type = ["code"]
							redirect_uris  = ["https://example.com/callback"]
							claims         = "not-an-array"  # Invalid - should fail validation
						}
					}
					
					advanced_settings = jsonencode({
						app_auth = "oidc"
					})
				}
			`,
			expectError: true,
		},
		"oidc_enabled_with_valid_claims": {
			config: `
				provider "eaa" {
					contractid = "test-contract"
				}

				resource "eaa_application" "test" {
					name            = "test-oidc-app"
					app_type        = "enterprise"
					app_profile     = "http"
					client_app_mode = "tcp"
					host            = "test.example.com"
					
					oidc_settings {
						oidc_clients {
							response_type = ["code"]
							redirect_uris  = ["https://example.com/callback"]
							claims {
								name  = "email"
								scope = "openid"
							}
						}
					}
					
					advanced_settings = jsonencode({
						app_auth = "oidc"
					})
				}
			`,
			expectError: false,
		},
		"oidc_not_enabled": {
			config: `
				provider "eaa" {
					contractid = "test-contract"
				}

				resource "eaa_application" "test" {
					name            = "test-app"
					app_type        = "enterprise"
					app_profile     = "http"
					client_app_mode = "tcp"
					host            = "test.example.com"
					
					advanced_settings = jsonencode({
						app_auth = "none"
					})
				}
			`,
			expectError: false, // Should skip validation when oidc not enabled
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			testStep := resource.TestStep{
				Config: tt.config,
			}

			if tt.expectError {
				if tt.errorText != "" {
					testStep.ExpectError = regexp.MustCompile(tt.errorText)
				} else {
					testStep.ExpectError = regexp.MustCompile(".*") // Match any error
				}
			} else {
				// For success cases, we just verify the plan can be created
				// The validation happens during CustomizeDiff which runs during plan
				testStep.PlanOnly = true
				testStep.ExpectNonEmptyPlan = true // We expect a plan (resource creation)
			}

			resource.UnitTest(t, resource.TestCase{
				ProviderFactories: UnitTestProviderFactories(),
				IsUnitTest:        true,
				Steps:             []resource.TestStep{testStep},
			})
		})
	}
}

// These tests use terraform-plugin-testing/helper/resource with PlanOnly: true to create
// proper *schema.ResourceDiff instances during Terraform plan operations.
//
// This approach:
// 1. Uses Terraform's testing framework to create real ResourceDiff instances (as in production)
// 2. Uses mocked providers (no real API calls) via UnitTestProviderFactories()
// 3. Is fast (unit-test speed with IsUnitTest: true)
// 4. Verifies actual Terraform behavior with real ResourceDiff instances
// 5. Tests the validation functions directly through CustomizeDiff using PlanOnly: true
//
// The functions isAuthProtocolEnabled and getFirstSettingsBlock are tested indirectly
// through ValidateWSFEDNestedBlocks, ValidateSAMLNestedBlocks, and ValidateOIDCNestedBlocks.
