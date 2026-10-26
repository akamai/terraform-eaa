# eaa_custom_app_certificate

Manages the lifecycle of an EAA custom application certificate (CERT_TYPE_APP).

## Example Usage

### Direct Input

resource "eaa_custom_app_certificate" "app_cert" {
  name        = "my-app-cert"
  cert        = file("certs/app.crt")
  private_key = file("certs/app.key")
  password    = "optional-password"
}

### Via Vault Provider

data "vault_generic_secret" "app_cert" {
  path = "secret/data/certs/app"
}

resource "eaa_custom_app_certificate" "app_cert" {
  name        = "my-app-cert"
  cert        = data.vault_generic_secret.app_cert.data["cert"]
  private_key = data.vault_generic_secret.app_cert.data["private_key"]
}

## Argument Reference

- `name` - (Required) Certificate name.
- `cert` - (Optional at schema level, required for Create/Update) PEM-encoded certificate content. Use `file()` to read from disk.
- `private_key` - (Optional at schema level, required for Create/Update) PEM-encoded private key. Sensitive. Use `file()` to read from disk.
- `password` - (Optional) Certificate password. Sensitive. Defaults to empty string.

## Attribute Reference

- `uuid_url` - Certificate UUID.
- `cn` - Common name.
- `subject` - Certificate subject.
- `issuer` - Certificate issuer.
- `issued_at` - Issue date.
- `expired_at` - Expiry date.
- `days_left` - Days until expiry.
- `status` - Certificate status.
- `app_count` - Number of associated applications.
- `dir_count` - Number of associated directories.
- `cert_type` - Certificate type (always "1" for this resource).
- `private_key_sha256` - SHA256 hash of the private key for change detection.
- `created_at` - Creation timestamp.
- `modified_at` - Last modified timestamp.
- `apps` - List of associated applications (name, uuid_url, status).
- `idps` - List of associated IDPs (name, uuid_url, status).
- `cert_idps` - List of certificate IDPs (name, uuid_url, status).
- `client_cert_idps` - List of client certificate IDPs (name, uuid_url, status).
- `saml_cert_idps` - List of SAML certificate IDPs (name, uuid_url, status).
- `saml_custom_sign_cert_idps` - List of SAML custom sign certificate IDPs (name, uuid_url, status).

## Import

terraform import eaa_custom_app_certificate.example <uuid_url>

After import, the first update requires `cert` and `private_key` to be provided.

## Update Behavior

On update, the provider sends the full certificate and private key to the API. If the certificate is associated with applications, the provider automatically deploys it. If auto-deploy fails or the certificate is not associated, a warning is emitted listing the applications and IDPs that need manual redeployment.
