# Application data source
# Reads an existing application by name or by uuid_url. All attributes are read-only.

terraform {
  required_providers {
    eaa = {
      source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "2.0.0"
    }
  }
}

provider "eaa" {
  contractid = "XXXXXXX"
  edgerc     = ".edgerc"
}

# Look up by exact application name (errors if zero or several apps match)
data "eaa_application" "by_name" {
  name = "Web App"
}

# Look up by UUID, resolved from the app list
data "eaa_data_source_apps" "all" {}

data "eaa_application" "by_uuid" {
  uuid_url = one([for a in data.eaa_data_source_apps.all.apps : a.uuid_url if a.name == "Web App"])
}

output "app_host" {
  value = data.eaa_application.by_name.host
}

output "app_cname" {
  value = data.eaa_application.by_name.cname
}

output "app_g2o_key" {
  value     = data.eaa_application.by_name.advanced_settings["g2o_key"]
  sensitive = true
}

output "app_uuid_url" {
  value = data.eaa_application.by_uuid.uuid_url
}
