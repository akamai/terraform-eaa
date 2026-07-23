# -------------------------------------------------------
# Example 1: Certificate from local files
# -------------------------------------------------------
resource "eaa_custom_app_certificate" "from_file" {
  name        = "app-cert-from-file"
  cert        = file("certs/app.crt")
  private_key = file("certs/app.key")
  password    = ""
}

# -------------------------------------------------------
# Example 2: Certificate from inline strings
# -------------------------------------------------------
resource "eaa_custom_app_certificate" "from_string" {
  name = "app-cert-from-string"

  cert = <<-EOT
    -----BEGIN CERTIFICATE-----
    MIIDXTCCAkWgAwIBAgIJAMoS...
    -----END CERTIFICATE-----
  EOT

  private_key = <<-EOT
    -----BEGIN PRIVATE KEY-----
    MIIEvgIBADANBgkqhkiG9w0B...
    -----END PRIVATE KEY-----
  EOT
}

# -------------------------------------------------------
# Example 3: Certificate from HashiCorp Vault (KV)
# -------------------------------------------------------
terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 5.0"
    }
  }
}

data "vault_kv_secret_v2" "app_cert" {
  mount = "secret"
  name  = "certs/app"
}

resource "eaa_custom_app_certificate" "from_vault_kv" {
  name        = "app-cert-from-vault-kv"
  cert        = data.vault_kv_secret_v2.app_cert.data["cert"]
  private_key = data.vault_kv_secret_v2.app_cert.data["private_key"]
  password    = lookup(data.vault_kv_secret_v2.app_cert.data, "password", "")
}

# -------------------------------------------------------
# Example 4: Certificate from HashiCorp Vault (PKI)
# -------------------------------------------------------
terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 5.0"
    }
  }
}

data "vault_pki_secret_backend_cert" "app_cert" {
  backend     = "pki"
  name        = "web-server"
  common_name = "app.example.com"
}

resource "eaa_custom_app_certificate" "from_vault_pki" {
  name        = "app-cert-from-vault-pki"
  cert        = data.vault_pki_secret_backend_cert.app_cert.certificate
  private_key = data.vault_pki_secret_backend_cert.app_cert.private_key
}

# -------------------------------------------------------
# Outputs
# -------------------------------------------------------
output "file_cert_uuid" {
  value = eaa_custom_app_certificate.from_file.uuid_url
}

output "file_cert_expiry" {
  value = eaa_custom_app_certificate.from_file.expired_at
}

output "vault_kv_cert_apps" {
  value = eaa_custom_app_certificate.from_vault_kv.apps
}
