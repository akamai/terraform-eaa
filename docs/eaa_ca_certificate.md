# eaa_ca_certificate

Manages the lifecycle of an EAA CA certificate (CERT_TYPE_CA).

## Example Usage

resource "eaa_ca_certificate" "ca_cert" {
  name = "my-ca-cert"
  cert = file("certs/ca.crt")
}

## Argument Reference

- `name` - (Required) Certificate name.
- `cert` - (Required) PEM-encoded CA certificate content. Use `file()` to read from disk.
- `password` - (Optional) Certificate password. Sensitive. Defaults to empty string.

## Attribute Reference

- `uuid_url` - Certificate UUID.
- `cn` - Common name.
- `subject` - Certificate subject.
- `issuer` - Certificate issuer.
- `issued_at` - Issue date.
- `expired_at` - Expiry date.
- `days_left` - Days until expiry.
- `cert_file_name` - Original filename from upload.
- `status` - Certificate status.
- `app_count` - Number of associated applications.
- `dir_count` - Number of associated directories.
- `cert_type` - Certificate type (always "6" for this resource).
- `created_at` - Creation timestamp.
- `modified_at` - Last modified timestamp.
- `apps` - List of associated applications (name, uuid_url, status).
- `idps` - List of associated IDPs (name, uuid_url, status).
- `cert_idps` - List of certificate IDPs (name, uuid_url, status).
- `client_cert_idps` - List of client certificate IDPs (name, uuid_url, status).
- `saml_cert_idps` - List of SAML certificate IDPs (name, uuid_url, status).
- `saml_custom_sign_cert_idps` - List of SAML custom sign certificate IDPs (name, uuid_url, status).

## Import

terraform import eaa_ca_certificate.example <uuid_url>

## Update Behavior

On update, the provider uploads the new certificate content via multipart/form-data to the upload endpoint.
