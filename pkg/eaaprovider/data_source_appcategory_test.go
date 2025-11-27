package eaaprovider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestDataAppCategory tests the data source for app categories
// These tests use mocked providers (no .edgerc required, no real API calls)
func TestDataAppCategory(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	tests := map[string]struct {
		config      string
		checkFuncs  []resource.TestCheckFunc
		expectError bool
	}{
		"basic_read": {
			config: testAccEaaAppCategoriesConfig_basic(),
			checkFuncs: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("data.eaa_data_source_appcategories.appcategories", "id", "eaa_appcategories"),
				resource.TestCheckResourceAttrSet("data.eaa_data_source_appcategories.appcategories", "appcategories.#"),
			},
			expectError: false,
		},
		"verify_appcategory_fields": {
			config: testAccEaaAppCategoriesConfig_basic(),
			checkFuncs: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("data.eaa_data_source_appcategories.appcategories", "id", "eaa_appcategories"),
				// Verify at least one app category exists
				resource.TestCheckResourceAttrSet("data.eaa_data_source_appcategories.appcategories", "appcategories.0.name"),
				resource.TestCheckResourceAttrSet("data.eaa_data_source_appcategories.appcategories", "appcategories.0.uuid_url"),
			},
			expectError: false,
		},
		"verify_multiple_appcategories": {
			config: testAccEaaAppCategoriesConfig_basic(),
			checkFuncs: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("data.eaa_data_source_appcategories.appcategories", "id", "eaa_appcategories"),
				// Verify multiple app categories exist (if mock returns multiple)
				resource.TestCheckResourceAttrSet("data.eaa_data_source_appcategories.appcategories", "appcategories.#"),
				// Verify first app category exists
				resource.TestCheckResourceAttrSet("data.eaa_data_source_appcategories.appcategories", "appcategories.0.name"),
				resource.TestCheckResourceAttrSet("data.eaa_data_source_appcategories.appcategories", "appcategories.0.uuid_url"),
			},
			expectError: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			testStep := resource.TestStep{
				Config: tt.config,
			}

			if tt.expectError {
				testStep.ExpectError = regexp.MustCompile(".*")
			} else {
				testStep.Check = resource.ComposeAggregateTestCheckFunc(tt.checkFuncs...)
			}

			resource.UnitTest(t, resource.TestCase{
				ProviderFactories: UnitTestProviderFactories(),
				IsUnitTest:        true,
				Steps:             []resource.TestStep{testStep},
			})
		})
	}
}

func testAccEaaAppCategoriesConfig_basic() string {
	return `
	provider "eaa" {
		contractid = "test-contract"
	}

	data "eaa_data_source_appcategories" "appcategories" {
	}
`
}
