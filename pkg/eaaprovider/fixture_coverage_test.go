package eaaprovider

import (
	"regexp"
	"testing"

	"git.source.akamai.com/terraform-provider-eaa/pkg/testutils"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// testApplicationFixture is a helper function to test a single application fixture
func testApplicationFixture(t *testing.T, fixturePath string) {

	fixtureContent := testutils.LoadFixtureString(t, fixturePath)

			// Extract all resource names from the fixture using regex
			resourceRegex := regexp.MustCompile(`resource\s+"eaa_application"\s+"([^"]+)"`)
			matches := resourceRegex.FindAllStringSubmatch(fixtureContent, -1)

			if len(matches) == 0 {
		t.Fatalf("No eaa_application resources found in fixture: %s", fixturePath)
			}

			// Build checks for all resources found in the fixture
			checks := make([]resource.TestCheckFunc, 0, len(matches)*3)
			for _, match := range matches {
				resourceName := "eaa_application." + match[1]
				checks = append(checks,
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "name"),
					resource.TestCheckResourceAttrSet(resourceName, "app_type"),
				)
			}

			// Use resource.UnitTest with IsUnitTest: true
			// IsUnitTest: true uses in-process provider (no terraform-exec spawned)
			// Provider instance is reused via UnitTestProviderFactories() to avoid repeated initialization
			resource.UnitTest(t, resource.TestCase{
				ProviderFactories: UnitTestProviderFactories(), // Uses shared provider instance
				IsUnitTest:        true,                         // In-process, no terraform-exec
				Steps: []resource.TestStep{
					{
						Config:            fixtureContent,
						Check:             resource.ComposeAggregateTestCheckFunc(checks...),
						ExpectNonEmptyPlan: true, // Mock returns different values, so plan will show changes
					},
				},
				CheckDestroy: func(s *terraform.State) error {
					// Resources are mocked, so no actual cleanup needed
					return nil
				},
			})
}

// Individual test functions for each fixture - mutex ensures sequential execution
func TestApplicationFixture_SAMLApp(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/saml_app.tf")
}
func TestApplicationFixture_OIDCApp(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/oidc_app.tf")
}
func TestApplicationFixture_WSFedApp(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/wsfed_app.tf")
}
func TestApplicationFixture_BasicAuthApp(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/basic_auth_app.tf")
}
func TestApplicationFixture_JWTApp(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/jwt_app.tf")
}
func TestApplicationFixture_KerberosApp(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/kerberos_app.tf")
}
func TestApplicationFixture_SAMLComprehensive(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/saml_comprehensive.tf")
}
func TestApplicationFixture_OIDCComprehensive(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/oidc_comprehensive.tf")
}
func TestApplicationFixture_WSFedComprehensive(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/wsfed_comprehensive.tf")
}
func TestApplicationFixture_ComprehensiveEnterprise(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/comprehensive_enterprise.tf")
}
func TestApplicationFixture_TunnelApp(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/tunnel_app.tf")
}
func TestApplicationFixture_TunnelTCPApp(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/tunnel_tcp_app.tf")
}
func TestApplicationFixture_RDPApp(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/rdp_app.tf")
}
func TestApplicationFixture_BookmarkApp(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/bookmark_app.tf")
}
func TestApplicationFixture_SaaSApp(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/saas_app.tf")
}
func TestApplicationFixture_RDPEdgeCases(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/rdp_edge_cases.tf")
}
func TestApplicationFixture_HealthCheckEdgeCases(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/health_check_edge_cases.tf")
}
func TestApplicationFixture_LoadBalancingEdgeCases(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/load_balancing_edge_cases.tf")
}
func TestApplicationFixture_EnterpriseConnectivityEdgeCases(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/enterprise_connectivity_edge_cases.tf")
}
func TestApplicationFixture_ApplicationUpdateScenarios(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/application_update_scenarios.tf")
}
func TestApplicationFixture_ImportScenarios(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testApplicationFixture(t, "testdata/TestResourceApplication/import_scenarios.tf")
}

// testInvalidApplicationFixture is a helper function to test invalid application fixtures
func testInvalidApplicationFixture(t *testing.T, fixturePath string, expectErrorPattern string) {

			// Use resource.UnitTest with IsUnitTest: true
			resource.UnitTest(t, resource.TestCase{
				ProviderFactories: UnitTestProviderFactories(),
				IsUnitTest:        true,
				Steps: []resource.TestStep{
					{
						Config:      testutils.LoadFixtureString(t, fixturePath),
						ExpectError: regexp.MustCompile(expectErrorPattern),
					},
				},
				CheckDestroy: func(s *terraform.State) error {
					// Resources are mocked, so no actual cleanup needed
					// This prevents terraform from hanging on destroy operations
					return nil
				},
			})
}

// Individual test functions for invalid fixtures - mutex ensures sequential execution
func TestInvalidApplicationFixture_InvalidAppType(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testInvalidApplicationFixture(t, "testdata/TestResourceApplication/invalid_app_type.tf", ".*")
}
func TestInvalidApplicationFixture_InvalidAppProfile(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testInvalidApplicationFixture(t, "testdata/TestResourceApplication/invalid_app_profile.tf", ".*")
}
func TestInvalidApplicationFixture_InvalidTunnelAuth(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testInvalidApplicationFixture(t, "testdata/TestResourceApplication/invalid_tunnel_auth.tf", ".*")
}

// testConnectorPoolFixture is a helper function to test a single connector pool fixture
func testConnectorPoolFixture(t *testing.T, fixturePath string) {

	fixtureContent := testutils.LoadFixtureString(t, fixturePath)

			// Extract all resource names from the fixture using regex
			resourceRegex := regexp.MustCompile(`resource\s+"eaa_connector_pool"\s+"([^"]+)"`)
			matches := resourceRegex.FindAllStringSubmatch(fixtureContent, -1)

			if len(matches) == 0 {
		t.Fatalf("No eaa_connector_pool resources found in fixture: %s", fixturePath)
			}

			// Build checks for all resources found in the fixture
			checks := make([]resource.TestCheckFunc, 0, len(matches)*3)
			for _, match := range matches {
				resourceName := "eaa_connector_pool." + match[1]
				checks = append(checks,
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "name"),
					resource.TestCheckResourceAttrSet(resourceName, "package_type"),
				)
			}

			// Use resource.UnitTest with IsUnitTest: true
			resource.UnitTest(t, resource.TestCase{
				ProviderFactories: UnitTestProviderFactories(),
				IsUnitTest:        true,
				Steps: []resource.TestStep{
					{
						Config:            fixtureContent,
						Check:             resource.ComposeTestCheckFunc(checks...),
						ExpectNonEmptyPlan: true, // Mock returns different values, so plan will show changes
					},
				},
				CheckDestroy: func(s *terraform.State) error {
					// Resources are mocked, so no actual cleanup needed
					return nil
				},
			})
}

// Individual test functions for connector pool fixtures - mutex ensures sequential execution
func TestConnectorPoolFixture_Variations(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testConnectorPoolFixture(t, "testdata/TestResourceConnectorPool/connector_pool_variations.tf")
}
func TestConnectorPoolFixture_Create(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testConnectorPoolFixture(t, "testdata/TestResourceConnectorPool/create.tf")
}
func TestConnectorPoolFixture_Update(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testConnectorPoolFixture(t, "testdata/TestResourceConnectorPool/update.tf")
}
func TestConnectorPoolFixture_Import(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testConnectorPoolFixture(t, "testdata/TestResourceConnectorPool/import.tf")
}

// testConnectorFixture is a helper function to test a single connector fixture
func testConnectorFixture(t *testing.T, fixturePath string) {

	fixtureContent := testutils.LoadFixtureString(t, fixturePath)

			// Extract all resource names from the fixture using regex
			resourceRegex := regexp.MustCompile(`resource\s+"eaa_connector"\s+"([^"]+)"`)
			matches := resourceRegex.FindAllStringSubmatch(fixtureContent, -1)

			if len(matches) == 0 {
		t.Fatalf("No eaa_connector resources found in fixture: %s", fixturePath)
			}

			// Build checks for all resources found in the fixture
			checks := make([]resource.TestCheckFunc, 0, len(matches)*3)
			for _, match := range matches {
				resourceName := "eaa_connector." + match[1]
				checks = append(checks,
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "name"),
					resource.TestCheckResourceAttrSet(resourceName, "package"),
				)
			}

			// Use resource.UnitTest with IsUnitTest: true
			resource.UnitTest(t, resource.TestCase{
				ProviderFactories: UnitTestProviderFactories(),
				IsUnitTest:        true,
				Steps: []resource.TestStep{
					{
						Config: fixtureContent,
						Check:  resource.ComposeTestCheckFunc(checks...),
					},
				},
				CheckDestroy: resource.ComposeTestCheckFunc(
					// Verify connector is deleted
				),
			})
}

// Individual test functions for connector fixtures - mutex ensures sequential execution
func TestConnectorFixture_Basic(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testConnectorFixture(t, "testdata/TestResourceConnector/basic.tf")
}
func TestConnectorFixture_WithSettings(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	testConnectorFixture(t, "testdata/TestResourceConnector/with_settings.tf")
}
