# eaa_directory

Manages the lifecycle of an EAA Directory.

## Overview

The `eaa_directory` resource provides full CRUD support for EAA Directories. Directories store user and group information used for authentication and authorization in EAA applications.

Key features:
- Automatic rollback on create failure
- Name-based resolution for connectors
- Group search, assignment, and removal with set-based diffing
- Async verify and sync operations with polling
- Support for all directory types (AD, LDAP, Cloud, SAML, SCIM, etc.)

## Argument Reference

### Required

* `name` - (Required) Directory name.
* `service` - (Required, ForceNew) Directory type. Values: `AD`, `LDAP`, `OKTA`, `PINGONE`, `SAML`, `CLOUD`, `ONELOGIN`, `GOOGLE`, `AKAMAI`, `AKAMAI_MSP`, `LDS`, `SCIM`.

### Optional - Core Settings

* `description` - (Optional) Directory description.
* `host` - (Optional) LDAP server hostname or IP.
* `port` - (Optional, Computed) LDAP server port.
* `root_dn` - (Optional) Root distinguished name.
* `admin_user` - (Optional) LDAP admin bind username.
* `admin_pwd` - (Optional, Sensitive) LDAP admin bind password. Suppresses diff when old value exists and new value is empty.
* `ssl` - (Optional, Computed) Enable SSL for LDAP connection.
* `is_ssl_verification_enabled` - (Optional, Computed) Enable SSL certificate verification.
* `is_leda_dir` - (Optional) Whether this is a Leda-managed directory.
* `mfa` - (Optional, Computed) MFA mode.
* `logout_url` - (Optional) Logout URL.

### Optional - Connectors and Groups

* `agents` - (Optional, Set of strings) Connector names. Resolved to UUIDs internally via the agents list API.
* `groups` - (Optional, Set of strings) Group names to search and assign. On create, each group is searched in the directory and assigned. On update, groups are diffed — removed groups are disassociated, added groups are searched and assigned.

### Optional - LDAP Search/Filter

* `user_base_dn` - (Optional) Base DN for user searches.
* `user_search_filter` - (Optional, Computed) LDAP filter for user searches.
* `group_base_dn` - (Optional) Base DN for group searches.
* `group_search_filter` - (Optional, Computed) LDAP filter for group searches.
* `group_members` - (Optional, Computed) LDAP attribute for group members.
* `group_name_attr` - (Optional, Computed) LDAP attribute for group name.
* `group_token` - (Optional, Computed) LDAP attribute for primary group token.
* `user_display_name` - (Optional, Computed) LDAP attribute for display name.
* `user_email` - (Optional, Computed) LDAP attribute for email.
* `user_fname` - (Optional, Computed) LDAP attribute for first name.
* `user_lname` - (Optional, Computed) LDAP attribute for last name.
* `user_phone_num` - (Optional, Computed) LDAP attribute for phone number.
* `user_principal` - (Optional, Computed) LDAP attribute for user principal name.
* `user_samaccountname` - (Optional, Computed) LDAP attribute for sAMAccountName.
* `user_upn` - (Optional, Computed) LDAP attribute for UPN.
* `user_memberof` - (Optional, Computed) LDAP attribute for group membership.
* `user_memberuid` - (Optional, Computed) LDAP attribute for member UID.
* `ou_attr` - (Optional) OU attribute.
* `ou_filter` - (Optional) OU filter.

### Optional - List Attributes

* `user_object_classes` - (Optional, Computed) LDAP object classes for user entries.
* `group_object_classes` - (Optional, Computed) LDAP object classes for group entries.
* `ou_object_classes` - (Optional, Computed) LDAP object classes for OU entries.
* `host_aliases` - (Optional) Host aliases for LDAP server.
* `domains` - (Optional) Associated domains.

### Optional - Additional Settings

* `chase_referral` - (Optional, Computed) Chase LDAP referrals.
* `global_catalog` - (Optional, Computed) Use AD Global Catalog.
* `server_cert_validate` - (Optional, Computed) Validate server certificate.
* `auth_request_signed` - (Optional, Computed) Sign auth requests.
* `auth_response_encrypt` - (Optional, Computed) Encrypt auth responses.
* `password_change_allow` - (Optional, Computed) Allow password changes.
* `password_reset_allow` - (Optional, Computed) Allow password resets.
* `password_policy_default` - (Optional, Computed) Default password policy.
* `password_expire_warn_threshold` - (Optional, Computed) Days before expiry to warn.
* `password_change_threshold` - (Optional, Computed) Password change threshold.
* `password_complexity_message` - (Optional, Computed) Custom complexity message.
* `is_rate_limit_enabled` - (Optional, Computed) Enable rate limiting.
* `rate_limit_time_interval` - (Optional, Computed) Rate limit interval (seconds).
* `rate_limit_query_count` - (Optional, Computed) Max queries per interval.
* `scim_provider_id` - (Optional) SCIM provider ID.
* `company_id` - (Optional, Computed) Company identifier.
* `source` - (Optional) Source identifier.

### Optional - Map Attributes

* `attribute_map` - (Optional, Computed) Custom attribute mapping.
* `password_filter` - (Optional, Computed) Password filter rules.

## Attributes Reference

* `uuid_url` - Unique identifier.
* `created_at` - Creation timestamp.
* `modified_at` - Last modification timestamp.
* `localization` - Data center localization.
* `directory_type` - Directory type code.
* `directory_status` - Deployment status.
* `directory_deployed_status` - Deployed status.
* `cname` - Directory CNAME.
* `dialin_sni` - Dial-in SNI hostname.
* `sync_state` - Sync state.
* `sync_interval` - Sync interval in seconds.
* `last_sync` - Last sync timestamp.
* `user_count` - Number of users.
* `group_count` - Number of groups.
* `status` - Directory status.

## Create Flow

1. POST to create directory with name, service type, and description
2. GET current state, overlay user config, PUT to update
3. Verify directory connectivity (async polling, 5s interval, 2min timeout)
4. For each configured group: search (async), then assign
5. Verify groups are assigned, update directory with group info
6. Sync directory
7. On any failure: rollback by deleting the directory

## Update Flow

1. GET current state, overlay changes, PUT to update
2. If groups changed:
   - Sync before group changes
   - Diff old vs new groups using set operations
   - Remove disassociated groups by UUID
   - Search and assign new groups
   - Sync after group changes

## Gotchas

- `service` is **ForceNew** — changing the directory type destroys and recreates the resource
- `admin_pwd` is **Sensitive** and suppresses diff when old value exists but new value is empty (API never returns the password)
- Group assignment requires the directory to be verified first — the create flow handles this automatically
- Verify and search operations are async with polling (5-second intervals, 2-minute timeout)
- Connectors (`agents`) are resolved by name — use the same names as shown in the EAA console

## Import

```bash
terraform import eaa_directory.example <uuid_url>
```

The import tool (`bin/import-config`) also supports directory imports — select "Y" when prompted for directory import.
