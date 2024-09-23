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

resource "eaa_application" "sap-prod-dc1-app" {
    provider    = eaa

    app_profile     = "tcp"
    app_type        = "tunnel"
    client_app_mode = "tunnel"

    domain          = "wapp"
    popregion       = "us-west-1"

    name        = "SAP Production"
    description = "SAP Production TCP tunnel app created using terraform"
    host        = "sap-prod-dc1"

    agents = ["EAA_DC1_US1_TCP_01"]

    tunnel_internal_hosts {
        proto_type = 1
        port_range = "3200-6000"
        host       = "192.168.2.1"
    }

    tunnel_internal_hosts {
        proto_type = 1
        port_range = "40199"
        host       = "192.168.2.2"
    }

    advanced_settings {
        is_ssl_verification_enabled = "false"
        ip_access_allow = "false"
        x_wapp_read_timeout = "300"
	  }

    auth_enabled = "true"

    app_authentication {
        app_idp = "employees-idp"
        app_directories {
            name = "Cloud Directory"
            app_groups {
                name = "SAP-Admins"
            }
        }
    }
}