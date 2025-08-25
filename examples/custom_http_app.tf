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
        acceleration = "false"
        anonymous_server_conn_limit = "50"
        anonymous_server_request_limit = "100"
        app_auth_domain = "example.com"
        app_client_cert_auth = "false"
        app_location = "internal"
        app_server_read_timeout = "60"
        authenticated_server_conn_limit = "50"
        authenticated_server_request_limit = "100"
        client_cert_auth = "false"
        client_cert_user_param = "email"
        cookie_domain = "example.com"
        disable_user_agent_check = "false"
        domain_exception_list = "*.example.com"
        edge_transport_manual_mode = "true"
        edge_transport_property_id = "123"
        enable_client_side_xhr_rewrite = "false"
        external_cookie_domain = "external.example.com"
        force_ip_route = "false"
        force_mfa = "off"
        form_post_attributes = ["email", "name"]
        form_post_url = "https://example.com/post"
        forward_ticket_granting_ticket = "false"
        health_check_fall = "3"
        health_check_http_host_header = "example.com"
        health_check_http_url = "/"
        health_check_http_version = "1.1"
        health_check_interval = "30000"
        health_check_rise = "2"
        health_check_timeout = "50000"
        health_check_type = "Default"
        hidden_app = "false"
        host_key = "hostkey123"
        hsts_age = "15552000"
        http_only_cookie = "true"
        https_sslv3 = "false"
        idle_close_time_seconds = "1200"
        idle_conn_ceil = "75"
        idle_conn_floor = "50"
        idle_conn_step = "10"
        idp_idle_expiry = "3600"
        idp_max_expiry = "7200"
        ignore_bypass_mfa = "off"
        inject_ajax_javascript = "off"
        intercept_url = "/intercept"
        is_brotli_enabled = "false"
        keepalive_connection_pool = "50"
        keepalive_enable = "true"
        keepalive_timeout = "300"
        load_balancing_metric = "round-robin"
        logging_enabled = "true"
        login_timeout = "5"
        login_url = "https://example.com/login"
        mdc_enable = "false"
        mfa = "inherit"
        offload_onpremise_traffic = "false"
        onramp = "inherit"
        pass_phrase = "passphrase123"
        preauth_consent = "false"
        preauth_enforce_url = "https://example.com/preauth"
        private_key = "privatekey123"
        remote_spark_audio = "true"
        remote_spark_disk = "LOCALSHARE"
        remote_spark_map_clipboard = "on"
        remote_spark_map_disk = "true"
        remote_spark_map_printer = "true"
        remote_spark_printer = "printer1"
        remote_spark_recording = "false"
        request_body_rewrite = "false"
        request_parameters = {}
        saas_enabled = "false"
        segmentation_policy_enable = "false"
        sentry_restore_form_post = "off"
        server_cert_validate = "true"
        server_request_burst = "100"
        service_principle_name = "service@example.com"
        session_sticky = "false"
        session_sticky_cookie_maxage = "3600"
        session_sticky_server_cookie = "session_cookie"
        single_host_content_rw = "false"
        single_host_cookie_domain = "single.example.com"
        single_host_enable = "false"
        single_host_fqdn = "single.example.com"
        single_host_path = "/single"
        spdy_enabled = "true"
        ssh_audit_enabled = "false"
        sso = "true"
        user_name = "username"
        wapp_auth = "form"
        x_wapp_pool_enabled = "inherit"
        x_wapp_pool_size = 20
        x_wapp_pool_timeout = 120
        
        custom_headers = [
            {
                attribute_type = "custom"
                header = "myheader"
                attribute = "attributevalue"
            },
            {
                attribute_type = "user"
                header = "myuser"
                attribute = "user.email"
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
