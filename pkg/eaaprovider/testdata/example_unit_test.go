package eaaprovider

import (
	"regexp"
	"testing"

	"git.source.akamai.com/terraform-provider-eaa/pkg/testutils"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestApplicationResource demonstrates how to create unit tests using the testutils infrastructure
func TestApplicationResource(t *testing.T) {
	// Test resource creation
	t.Run("create", func(t *testing.T) {
		resource.UnitTest(t, resource.TestCase{
			ProviderFactories: UnitTestProviderFactories(),
			IsUnitTest:        true, // This makes it a fast unit test!
			Steps: []resource.TestStep{
				{
					Config: testutils.LoadFixtureString(t, "testdata/TestResourceApplication/create.tf"),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr("eaa_application.test", "name", "test-application"),
						resource.TestCheckResourceAttr("eaa_application.test", "app_type", "bookmark"),
						resource.TestCheckResourceAttr("eaa_application.test", "host", "example.com"),
						resource.TestCheckResourceAttrSet("eaa_application.test", "id"),
					),
				},
			},
		})
	})

	// Test resource updates
	t.Run("update", func(t *testing.T) {
		resource.UnitTest(t, resource.TestCase{
			ProviderFactories: UnitTestProviderFactories(),
			IsUnitTest:        true,
			Steps: []resource.TestStep{
				{
					Config: testutils.LoadFixtureString(t, "testdata/TestResourceApplication/create.tf"),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr("eaa_application.test", "name", "test-application"),
						resource.TestCheckResourceAttr("eaa_application.test", "host", "example.com"),
					),
				},
				{
					Config: testutils.LoadFixtureString(t, "testdata/TestResourceApplication/update.tf"),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr("eaa_application.test", "name", "test-application-updated"),
						resource.TestCheckResourceAttr("eaa_application.test", "host", "updated.example.com"),
					),
				},
			},
		})
	})

	// Test validation errors
	t.Run("validation_error", func(t *testing.T) {
		resource.UnitTest(t, resource.TestCase{
			ProviderFactories: UnitTestProviderFactories(),
			IsUnitTest:        true,
			Steps: []resource.TestStep{
				{
					Config:      testutils.LoadFixtureString(t, "testdata/TestResourceApplication/invalid.tf"),
					ExpectError: regexp.MustCompile("name cannot be empty"),
				},
			},
		})
	})

	// Test resource destruction
	t.Run("destroy", func(t *testing.T) {
		resource.UnitTest(t, resource.TestCase{
			ProviderFactories: UnitTestProviderFactories(),
			IsUnitTest:        true,
			Steps: []resource.TestStep{
				{
					Config: testutils.LoadFixtureString(t, "testdata/TestResourceApplication/create.tf"),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet("eaa_application.test", "id"),
					),
				},
				// Test destroy - empty config removes resource
				{
					Config:             "",
					ExpectNonEmptyPlan: false,
				},
			},
		})
	})
}

// TestApplicationDataSource demonstrates data source unit testing
func TestApplicationDataSource(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProviderFactories: UnitTestProviderFactories(),
		IsUnitTest:        true,
		Steps: []resource.TestStep{
			{
				Config: testutils.LoadFixtureString(t, "testdata/TestDataSourceApplication/basic.tf"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.eaa_application.test", "id"),
					resource.TestCheckResourceAttr("data.eaa_application.test", "name", "test-application"),
				),
			},
		},
	})
}

// TestApplicationImport demonstrates import testing
func TestApplicationImport(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProviderFactories: UnitTestProviderFactories(),
		IsUnitTest:        true,
		Steps: []resource.TestStep{
			{
				Config: testutils.LoadFixtureString(t, "testdata/TestResourceApplication/import.tf"),
			},
			{
				ResourceName:            "eaa_application.import_test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"created_at", "updated_at"},
			},
		},
	})
}

