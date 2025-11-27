package eaaprovider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestDataAgents tests the data source for agents
// These tests use mocked providers (no .edgerc required, no real API calls)
func TestDataAgents(t *testing.T) {
	AcquireTestLock()
	defer ReleaseTestLock()
	tests := map[string]struct {
		config      string
		checkFuncs  []resource.TestCheckFunc
		expectError bool
	}{
		"basic_read": {
			config: testAccEaaAgentsConfig_basic(),
			checkFuncs: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("data.eaa_data_source_agents.agents", "id", "eaa_agents"),
				resource.TestCheckResourceAttrSet("data.eaa_data_source_agents.agents", "agents.#"),
			},
			expectError: false,
		},
		"verify_agent_fields": {
			config: testAccEaaAgentsConfig_basic(),
			checkFuncs: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("data.eaa_data_source_agents.agents", "id", "eaa_agents"),
				// Verify at least one agent exists
				resource.TestCheckResourceAttrSet("data.eaa_data_source_agents.agents", "agents.0.name"),
				resource.TestCheckResourceAttrSet("data.eaa_data_source_agents.agents", "agents.0.uuid_url"),
				// Verify optional fields can be set (if present in mock response)
				resource.TestCheckResourceAttrSet("data.eaa_data_source_agents.agents", "agents.0.state"),
			},
			expectError: false,
		},
		"verify_multiple_agents": {
			config: testAccEaaAgentsConfig_basic(),
			checkFuncs: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("data.eaa_data_source_agents.agents", "id", "eaa_agents"),
				// Verify multiple agents exist (mock returns 2 agents)
				resource.TestCheckResourceAttr("data.eaa_data_source_agents.agents", "agents.#", "2"),
				// Verify first agent exists
				resource.TestCheckResourceAttrSet("data.eaa_data_source_agents.agents", "agents.0.name"),
				resource.TestCheckResourceAttrSet("data.eaa_data_source_agents.agents", "agents.0.uuid_url"),
				// Verify second agent exists
				resource.TestCheckResourceAttrSet("data.eaa_data_source_agents.agents", "agents.1.name"),
				resource.TestCheckResourceAttrSet("data.eaa_data_source_agents.agents", "agents.1.uuid_url"),
			},
			expectError: false,
		},
		"verify_agent_optional_fields": {
			config: testAccEaaAgentsConfig_basic(),
			checkFuncs: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("data.eaa_data_source_agents.agents", "id", "eaa_agents"),
				// Verify second agent has optional fields (if populated in mock)
				resource.TestCheckResourceAttrSet("data.eaa_data_source_agents.agents", "agents.1.reach"),
				resource.TestCheckResourceAttrSet("data.eaa_data_source_agents.agents", "agents.1.state"),
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
				ProviderFactories: UnitTestProviderFactories(), // uses the test factory, not the real provider
				IsUnitTest:        true,
				Steps:             []resource.TestStep{testStep},
			})
		})
	}
}

func testAccEaaAgentsConfig_basic() string {
	return `
	provider "eaa" {
		contractid = "test-contract"
	}

	data "eaa_data_source_agents" "agents" {
	}
`
}
