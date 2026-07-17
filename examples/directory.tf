# Cloud Directory — Minimal Config
resource "eaa_directory" "cloud_dir" {
  name    = "Cloud Directory"
  service = "CLOUD"
}

# Active Directory with Groups and Connectors
resource "eaa_directory" "corp_ad" {
  name        = "Corporate AD"
  description = "Main corporate Active Directory"
  service     = "AD"

  host       = "dc1.corp.example.com"
  port       = 389
  root_dn    = "DC=corp,DC=example,DC=com"
  admin_user = "CN=svc-eaa,OU=ServiceAccounts,DC=corp,DC=example,DC=com"
  admin_pwd  = var.ad_admin_password

  ssl                         = true
  is_ssl_verification_enabled = true

  agents = ["dc1-connector", "dc2-connector"]

  groups = ["Engineering", "IT-Admins", "VPN-Users"]

  user_base_dn        = "OU=Users,DC=corp,DC=example,DC=com"
  user_search_filter  = "(objectClass=user)"
  group_base_dn       = "OU=Groups,DC=corp,DC=example,DC=com"
  group_search_filter = "(objectClass=group)"

  chase_referral = true
  global_catalog = false

  password_change_allow          = true
  password_expire_warn_threshold = 14
}

# LDAP Directory with Full Search Filters
resource "eaa_directory" "ldap_dir" {
  name        = "OpenLDAP Directory"
  description = "OpenLDAP for application users"
  service     = "LDAP"

  host       = "ldap.example.com"
  port       = 636
  root_dn    = "dc=example,dc=com"
  admin_user = "cn=admin,dc=example,dc=com"
  admin_pwd  = var.ldap_admin_password

  ssl = true

  agents = ["ldap-connector"]

  user_base_dn       = "ou=people,dc=example,dc=com"
  user_search_filter = "(objectClass=inetOrgPerson)"
  user_display_name  = "cn"
  user_email         = "mail"
  user_fname         = "givenName"
  user_lname         = "sn"
  user_phone_num     = "telephoneNumber"
  user_principal     = "uid"
  user_memberof      = "memberOf"

  group_base_dn       = "ou=groups,dc=example,dc=com"
  group_search_filter = "(objectClass=groupOfNames)"
  group_members       = "member"
  group_name_attr     = "cn"

  user_object_classes  = ["inetOrgPerson", "posixAccount"]
  group_object_classes = ["groupOfNames"]

  groups = ["app-users", "app-admins"]
}

# Use directory in an IDP
resource "eaa_idp" "corp_idp" {
  name       = "Corp IDP"
  idp_type   = "EAA"
  login_host = "corp-login"

  directories = [
    eaa_directory.corp_ad.name,
    eaa_directory.cloud_dir.name,
  ]
}
