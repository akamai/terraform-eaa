package eaaprovider

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestDataAgents(t *testing.T) {
	t.Run("DataAgents", func(t *testing.T) {

		resource.Test(t, resource.TestCase{
			IsUnitTest:        false,
			ProviderFactories: testAccProviders,
			Steps: []resource.TestStep{
				{
					Config: testAccEaaAgentsConfigBasic(),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("data.eaa_data_source_agents.agents", "id", "eaa_agents"),
						func(s *terraform.State) error {

							attr := s.RootModule().Resources["data.eaa_data_source_agents.agents"].Primary.Attributes
							y1, _ := strconv.Atoi(attr["agents.#"])
							if y1 == 0 {
								return fmt.Errorf("0 agents")
							}
							i := 0
							for i = 0; i < y1; i++ {
								att := "agents." + strconv.Itoa(i) + ".name"
								if attr[att] == "terraform-test-connector" {
									break
								}
							}
							if i == y1 {
								return fmt.Errorf("terraform-test-connector not found")
							}
							return nil
						},
					),
				},
			},
		})
	})
}

func testAccEaaAgentsConfigBasic() string {
	return `
	data "eaa_data_source_agents" "agents"{
	}

	provider "eaa" {
		contractid = "1-3CV382"
		edgerc           = ".edgerc"

	}
`
}
