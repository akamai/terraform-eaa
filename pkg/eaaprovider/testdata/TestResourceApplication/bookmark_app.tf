
provider "eaa" {
  contractid = "test-contract-123"

}

# Bookmark Application - Basic Configuration
resource "eaa_application" "test" {
  name        = "test-bookmark-app"
  description = "Test bookmark application"
  app_type    = "bookmark"
  host        = "bookmark.example.com"
  domain      = "wapp"
}

