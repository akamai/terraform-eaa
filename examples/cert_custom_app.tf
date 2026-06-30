resource "eaa_custom_app_certificate" "app_cert" {
  name        = "my-app-cert"
  cert        = file("certs/app.crt")
  private_key = file("certs/app.key")
  password    = ""
}

output "app_cert_uuid" {
  value = eaa_custom_app_certificate.app_cert.uuid_url
}

output "app_cert_expiry" {
  value = eaa_custom_app_certificate.app_cert.expired_at
}
