# Enterprise RDP Application
# Remote desktop app with RDP-specific settings and remote app publishing.

terraform {
  required_providers {
    eaa = {
      source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "2.2.0"
    }
  }
}

provider "eaa" {
  contractid = "XXXXXXX"
  edgerc     = ".edgerc"
}

resource "eaa_application" "rdp_app" {
  name            = "Engineering Workstation"
  description     = "RDP access to shared engineering workstation"
  host            = "eng-workstation.example.com"
  app_profile     = "rdp"
  app_type        = "enterprise"
  domain          = "wapp"
  client_app_mode = "tcp"
  popregion       = "us-east-1"
  agents          = ["EAA_DC1_US1_Access_01"]

  servers {
    origin_protocol = "rdp"
    origin_port     = 3389
    origin_host     = "rdp-backend.example.com"
  }

  service {
    service_type = "access"
    status       = "on"

    access_rule {
      name   = "Allow All Users"
      status = "on"
      rule {
        operator = "=="
        type     = "user"
        value    = "*"
      }
    }
  }

  advanced_settings = {
    app_auth = "none"

    # RDP uses TCP health checks (not HTTP)
    health_check_type     = "TCP"
    health_check_interval = "30000"
    health_check_timeout  = "50000"
    health_check_rise     = "3"
    health_check_fall     = "3"

    # RDP-specific settings
    rdp_initial_program    = "notepad.exe"
    rdp_tls1               = "true"
    remote_spark_recording = "true"

    # rdp_remote_apps publishes individual apps via RemoteApp; must be jsonencode'd
    rdp_remote_apps = jsonencode([
      {
        remote_app      = "Calculator"
        remote_app_args = "/s"
        remote_app_dir  = "C:\\Windows\\System32"
      }
    ])

    idle_conn_floor         = "10"
    idle_conn_ceil          = "100"
    idle_conn_step          = "10"
    idle_close_time_seconds = "300"
    logging_enabled         = "true"
    hidden_app              = "false"
    sticky_agent            = "true"
  }
}
