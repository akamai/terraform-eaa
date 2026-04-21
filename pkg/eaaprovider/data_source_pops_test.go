package eaaprovider

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestDataPops(t *testing.T) {
	t.Run("DataPops", func(t *testing.T) {

		resource.Test(t, resource.TestCase{
			IsUnitTest:        false,
			ProviderFactories: testAccProviders,
			Steps: []resource.TestStep{
				{
					Config: testAccEaaAppPopsConfigBasic(),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("data.eaa_data_source_pops.pops", "id", "eaa_pops"),
						func(s *terraform.State) error {

							attr := s.RootModule().Resources["data.eaa_data_source_pops.pops"].Primary.Attributes
							y1, _ := strconv.Atoi(attr["pops.#"])
							if y1 == 0 {
								return fmt.Errorf("0 pops")
							}
							i := 0
							for i = 0; i < y1; i++ {
								att := "pops." + strconv.Itoa(i) + ".region"
								if strings.HasPrefix(attr[att], "us-west") == true {
									break
								}
							}
							if i == y1 {
								return fmt.Errorf("us-west not found")
							}
							return nil
						},
					),
				},
			},
		})
	})
}

func testAccEaaAppPopsConfigBasic() string {
	return `
	data "eaa_data_source_pops" "pops"{
	}

	provider "eaa" {
		contractid = "1-3CV382"
		edgerc     = ".edgerc"

	}
`
}
