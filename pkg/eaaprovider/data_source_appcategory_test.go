package eaaprovider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	// "github.com/stretchr/testify/mock"
	// client "git.source.akamai.com/terraform-provider-eaa/pkg/client" // Adjust this import
)

func TestDataAppCategory(t *testing.T) {
	t.Run("DataAppCategory", func(t *testing.T) {
		// mockedeaaproviderClient := &client.Mock{}

		// response := []client.AppCate{}

		// mockedeaaproviderClient.On("GetAppCategories", mock.Anything, client.EaaClient{}).Return(&response, nil)

		resource.Test(t, resource.TestCase{
			IsUnitTest:        false,
			ProviderFactories: testAccProviders,
			Steps: []resource.TestStep{
				{
					Config: testAccEaaAppCategoriesConfig_basic(),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("data.eaa_data_source_appcategories.appcategories", "appcategories.#", "1"),
						resource.TestCheckResourceAttr("data.eaa_data_source_appcategories.appcategories", "id", "eaa_appcategories"),
					),
				},
			},
		})
		// mockedeaaproviderClient.AssertExpectations(t)
	})
}

func testAccEaaAppCategoriesConfig_basic() string {
	return `
	data "eaa_data_source_appcategories" "appcategories"{
	}

	provider "eaa" {
		contractid = "1-3CV382"
		edgerc           = ".edgerc"

	}
`
}
