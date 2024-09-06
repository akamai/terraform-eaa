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

resource "eaa_application" "tfapp5" {
  provider = eaa

  name        = "tfapp5"
  description = "app created using terraform"
  host        = "terraformapp500" /* Application Name */

  app_profile = "http"
  app_type    = "enterprise"

  client_app_mode = "tcp"

  domain = "custom"
  cert_type = "self_signed"
  generate_self_signed_cert = true

  auth_enabled = "true"

  agents = ["Connector_to_be_assigned"]

  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "origin-perftest.akamaidemo.net"
  }

  advanced_settings {
      is_ssl_verification_enabled = "false"
      ignore_cname_resolution = "true"
      g2o_enabled = "true"
      edge_authentication_enabled = "true"
	}

  popregion = "us-east-1"

  app_authentication {
    app_idp = "idp_to_assign"
    
    app_directories {
      name = "dir_to_assign"
      app_groups {
        name = "group1"
      }
      app_groups {
        name = "group2"
      }
    }

  }
}



resource "eaa_application" "tfapp7" {
  provider = eaa

  name        = "tfapp7"
  description = "app created using terraform"
  host        = "terraformapp700" /* Application Name */

  app_profile = "http"
  app_type    = "enterprise"

  client_app_mode = "tcp"

  domain = "custom"
  cert_type = "uploaded"
  cert_name = "uploaded_cert_name"

  auth_enabled = "true"

  agents = ["Connector_to_be_assigned"]

  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "origin-perftest.akamaidemo.net"
  }

  advanced_settings {
      is_ssl_verification_enabled = "false"
      ignore_cname_resolution = "true"
      g2o_enabled = "true"
      edge_authentication_enabled = "true"
	}

  popregion = "us-east-1"

  app_authentication {
    app_idp = "idp_to_assign"

    app_directories {
      name = "dir_to_assign"
      app_groups {
        name = "group1"
      }
      app_groups {
        name = "group2"
      }
    }

  }
}


