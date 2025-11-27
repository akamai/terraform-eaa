package testutils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadFixtureString(t *testing.T) {
	// Test loading an existing fixture
	content := LoadFixtureString(t, "testdata/TestResourceApplication/create.tf")
	
	assert.NotEmpty(t, content, "Fixture content should not be empty")
	assert.Contains(t, content, "eaa_application", "Fixture should contain eaa_application resource")
	assert.Contains(t, content, "test-application", "Fixture should contain test application name")
}

func TestLoadFixtureStringf(t *testing.T) {
	// Test loading with format string
	content := LoadFixtureStringf(t, "testdata/TestResourceApplication/%s.tf", "create")
	
	assert.NotEmpty(t, content, "Fixture content should not be empty")
	assert.Contains(t, content, "eaa_application", "Fixture should contain eaa_application resource")
}

func TestLoadFixtureBytes(t *testing.T) {
	// Test loading as bytes
	content := LoadFixtureBytes(t, "testdata/TestResourceApplication/create.tf")
	
	assert.NotEmpty(t, content, "Fixture bytes should not be empty")
	assert.Greater(t, len(content), 100, "Fixture should have reasonable size")
}

// Test all new fixtures can be loaded
func TestLoadAllNewFixtures(t *testing.T) {
	fixtures := []string{
		"testdata/TestResourceApplication/tunnel_app.tf",
		"testdata/TestResourceApplication/saml_app.tf",
		"testdata/TestResourceApplication/oidc_app.tf",
		"testdata/TestResourceApplication/wsfed_app.tf",
		"testdata/TestResourceApplication/rdp_app.tf",
		"testdata/TestResourceApplication/comprehensive_enterprise.tf",
		"testdata/TestResourceApplication/bookmark_app.tf",
		"testdata/TestResourceApplication/saas_app.tf",
		"testdata/TestResourceApplication/invalid_app_type.tf",
		"testdata/TestResourceApplication/invalid_app_profile.tf",
		"testdata/TestResourceApplication/invalid_tunnel_auth.tf",
		"testdata/TestResourceConnectorPool/create.tf",
		"testdata/TestResourceConnectorPool/update.tf",
		"testdata/TestResourceConnectorPool/invalid.tf",
		"testdata/TestResourceConnectorPool/import.tf",
	}

	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			content := LoadFixtureString(t, fixture)
			assert.NotEmpty(t, content, "Fixture %s should not be empty", fixture)
			assert.Greater(t, len(content), 50, "Fixture %s should have reasonable size", fixture)
		})
	}
}
