resource "eaa_ca_certificate" "ca_cert" {
  name = "my-ca-cert"
  cert = file("certs/ca.crt")
}

output "ca_cert_uuid" {
  value = eaa_ca_certificate.ca_cert.uuid_url
}

output "ca_cert_expiry" {
  value = eaa_ca_certificate.ca_cert.expired_at
}
