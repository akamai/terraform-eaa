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

    advanced_settings = jsonencode({
        app_auth = "basic"
        allow_cors = "true"
        cors_method_list = "method1,method2"
        cors_origin_list = "origin1,origin2,orign3"
        cors_header_list = "header1,header2,header3"
        cors_max_age = 90000
        cors_support_credential = "off"
        sticky_agent = "false"
        websocket_enabled = "false"
        sentry_redirect_401 = "false"
        logout_url = "logout_url"
        app_auth_domain = "example.com"
        app_client_cert_auth = "false"
        app_server_read_timeout = "60"
        cookie_domain = "example.com"
        disable_user_agent_check = "false"
        form_post_url = "https://example.com/post"
        forward_ticket_granting_ticket = "false"
        health_check_fall = "3"
        health_check_http_host_header = "example.com"
        health_check_http_url = "/"
        health_check_http_version = "1.1"
        health_check_interval = "30000"
        health_check_rise = "2"
        health_check_timeout = "50000"
        health_check_type = "HTTP"
        hidden_app = "false"
        hsts_age = "15552000"
        http_only_cookie = "true"
        https_sslv3 = "false"
        idle_close_time_seconds = "1200"
        idle_conn_ceil = "75"
        idle_conn_floor = "50"
        idle_conn_step = "10"
        intercept_url = "/intercept"
        load_balancing_metric = "round-robin"
        logging_enabled = "true"
        login_url = "https://example.com/login"
        offload_onpremise_traffic = "false"
        preauth_consent = "false"
        saas_enabled = "false"
        sentry_restore_form_post = "off"
        service_principle_name = "service@example.com"
        session_sticky = "true"
        session_sticky_cookie_maxage = "3600"
        session_sticky_server_cookie = "session_cookie"
        wapp_auth = "form"
        custom_headers = [
            {
                attribute_type = "custom"
                header = "myheader"
                attribute = "value"
                
            },
            {
                attribute_type = "user"
                header = "myuser"
                attribute = ""
                
            }
        ]
    })

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
