terraform {
    required_providers {
        eaa = {
            source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
            version = "1.0.0"
        }
    }
}

provider "eaa" {
    contractid       = "XXXXXXX"
    edgerc           = ".edgerc"
}

resource "eaa_application" "sql-lab-dc1-app" {
    provider    = eaa

    app_profile     = "tcp"
    app_type        = "tunnel"
    client_app_mode = "tcp"

    popregion       = "us-west-1"
    domain          = "wapp"

    name        = "SQL DB Lab Instance"
    description = "SQL DB Lab instance as TCP tunnel app created using terraform"
    host        = "sql-lab-dc1"

    servers {
        orig_tls        = true
        origin_protocol = "tcp"
        origin_port     = 3200
        origin_host     = "192.168.2.1"
    }

    agents = ["EAA_DC1_US1_TCP_01"]

    advanced_settings {
        is_ssl_verification_enabled = "false"
        ip_access_allow = "false"
        x_wapp_read_timeout = "300"
        internal_host_port = "300"
        internal_hostname = "myhost999.com"
	  }

    auth_enabled = "true"

    app_authentication {
        app_idp = "employees-idp"
        app_directories {
            name = "Cloud Directory"
            app_groups {
                name = "finance_group"
            }
        }
    }
}