terraform {
    required_providers {
    eaa = {
      source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "1.0.0"
    }
  }
}

provider "eaa" {
  contractid       = "W-Y0Q4V8"
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

    name         = "App All Subject Types Test 2025"
    description  = "Testing all subject types and configurations"
    host         = "app-all-subject-types-test-2025" /* Application Name */

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
        allow_cors = "true"
        cors_method_list = "method1,method2"
        cors_origin_list = "origin1,origin2,orign3"
        cors_header_list = "header1,header2,header3"
        cors_max_age = 90000
        cors_support_credential = "off"
        sticky_agent = "false"
        websocket_enabled = "false"
        sentry_redirect_401 = "off"
        logout_url = "logout_url"
        app_auth = "SAML2.0"
        custom_headers {
            attribute_type = "custom"
            header = "myheader"
            attribute = "attributevalue"
        }
        custom_headers {
            attribute_type = "user"
            header = "myuser"
        }
	}

    auth_enabled = "true"

    app_authentication {
        app_idp = "Philippine Charity Sweepstakes Office"

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