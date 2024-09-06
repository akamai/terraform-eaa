terraform {
    required_providers {
    eaa = {
      source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "1.0.0"
    }
  }
}

provider "eaa" {
  contractid       = "1-3XXXXX"
  edgerc           = ".edgerc"
}

resource "eaa_application" "jira-app" {
    provider = eaa

    app_profile = "http"
    app_type    = "enterprise"
    client_app_mode = "tcp"

    app_category = "Development"

    popregion    = "us-east-1"
    domain = "wapp"

    name         = "JIRA Application"
    description  = "Web-based JIRA app created using terraform"
    host         = "jira-app" /* Application Name */

    agents = ["EAA_DC1_US1_Access_01"]

    servers {
        orig_tls        = true
        origin_protocol = "https"
        origin_port     = 443
        origin_host     = "jira-app.example.com"
    }

    advanced_settings {
        is_ssl_verification_enabled = "false"
        ignore_cname_resolution = "true"
        g2o_enabled = "true"
	}

    auth_enabled = "true"

    app_authentication {
        app_idp = "employees-idp"

        app_directories {
            name = "Cloud Directory"
            app_groups {
                name = "Engineering"
            }
            app_groups {
                name = "SQA"
            }
        }
    }

    service {
        service_type = "access"
        status = "on"
        access_rule {
         name = "rule_name1"
         status = "on"
         rule {
            operator = "=="
            type = "group"
            value = "group_name"
         }
         rule {
             operator = "=="
             type = "user"
             value = "user_name"
         }
        }
        access_rule {
            name = "rule_name_2"
            status = "on"
            rule {
                operator = "=="
                type = "url"
                value = "url_string"
            }
        }
        access_rule {
            name = "rule_name_3"
            status = "off"
            rule {
                operator = "=="
                type = "url"
                value = "url_string"
            }
        }
    }
}