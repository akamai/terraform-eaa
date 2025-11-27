package eaaprovider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestDataPops tests the data source for POPs
// These tests use mocked providers (no .edgerc required, no real API calls)
func TestDataPops(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	tests := map[string]struct {
		config      string
		checkFuncs  []resource.TestCheckFunc
		expectError bool
	}{
		"basic_read": {
			config: testAccEaaAppPopsConfig_basic(),
			checkFuncs: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("data.eaa_data_source_pops.pops", "id", "eaa_pops"),
				resource.TestCheckResourceAttrSet("data.eaa_data_source_pops.pops", "pops.#"),
			},
			expectError: false,
		},
		"verify_pop_fields": {
			config: testAccEaaAppPopsConfig_basic(),
			checkFuncs: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("data.eaa_data_source_pops.pops", "id", "eaa_pops"),
				// Verify at least one pop exists with fields returned by mock
				resource.TestCheckResourceAttrSet("data.eaa_data_source_pops.pops", "pops.0.region"),
				resource.TestCheckResourceAttrSet("data.eaa_data_source_pops.pops", "pops.0.name"),
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

func testAccEaaAppPopsConfig_basic() string {
	return `
	provider "eaa" {
		contractid = "test-contract"
	}

	data "eaa_data_source_pops" "pops" {
	}
`
}
