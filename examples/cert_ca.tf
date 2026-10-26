# -------------------------------------------------------
# Example 1: CA certificate from local file
# -------------------------------------------------------
resource "eaa_ca_certificate" "from_file" {
  name = "ca-cert-from-file"
  cert = file("certs/ca.crt")
}

# -------------------------------------------------------
# Example 2: CA certificate from inline string
# -------------------------------------------------------
resource "eaa_ca_certificate" "from_string" {
  name = "ca-cert-from-string"

  cert = <<-EOT
    -----BEGIN CERTIFICATE-----
    MIIDXTCCAkWgAwIBAgIJAMoS...
    -----END CERTIFICATE-----
  EOT
}

# -------------------------------------------------------
# Example 3: CA certificate from HashiCorp Vault (KV)
# -------------------------------------------------------

terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 5.0"
    }
  }
}
data "vault_kv_secret_v2" "ca_cert" {
  mount = "secret"
  name  = "certs/ca"
}

resource "eaa_ca_certificate" "from_vault_kv" {
  name = "ca-cert-from-vault-kv"
  cert = data.vault_kv_secret_v2.ca_cert.data["cert"]
}

# -------------------------------------------------------
# Example 4: CA certificate from Vault PKI (issuing CA)
# -------------------------------------------------------

terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 5.0"
    }
  }
}
data "vault_pki_secret_backend_root_cert" "ca" {
  backend = "pki"
}

resource "eaa_ca_certificate" "from_vault_pki" {
  name = "ca-cert-from-vault-pki"
  cert = data.vault_pki_secret_backend_root_cert.ca.certificate
}

# -------------------------------------------------------
# Outputs
# -------------------------------------------------------
output "file_ca_uuid" {
  value = eaa_ca_certificate.from_file.uuid_url
}

output "file_ca_expiry" {
  value = eaa_ca_certificate.from_file.expired_at
}
