# Data Sources

See [examples/connector_pool.tf](../examples/connector_pool.tf) for working data source usage with `eaa_connector_pools`, `eaa_data_source_agents`, and `eaa_data_source_apps`.

## eaa_data_source_pops

Lists available EAA Points of Presence.

### Attributes

* `pops` - List of PoPs:
  * `name` - PoP name.
  * `region` - Region.
  * `description` - Description.
  * `facility` - Facility.
  * `pop_type` - PoP type.
  * `pop_category` - List of categories.
  * `uuid_url` - UUID.
  * `related_failover_pop` - Failover PoP UUID.
  * `related_failover_name` - Failover PoP name.

### Example

```hcl
data "eaa_data_source_pops" "all" {}

output "pop_regions" {
  value = [for p in data.eaa_data_source_pops.all.pops : p.region]
}
```

---

## eaa_data_source_appcategories

Lists available application categories.

### Attributes

* `appcategories` - List of categories:
  * `name` - Category name.
  * `uuid_url` - UUID.

### Example

```hcl
data "eaa_data_source_appcategories" "all" {}

output "categories" {
  value = [for c in data.eaa_data_source_appcategories.all.appcategories : c.name]
}
```

---

## eaa_data_source_agents

Lists all connectors (agents).

### Attributes

* `agents` - List of agents:
  * `name` - Agent name.
  * `uuid` - UUID.
  * `uuid_url` - UUID URL.
  * `reach` - Reachability (1=reachable, 0=unreachable).
  * `state` - State code.
  * `os_version` - OS version.
  * `public_ip` - Public IP.
  * `private_ip` - Private IP.
  * `type` - Agent type.
  * `region` - Region.
  * `connector_pool_uuid_url` - Parent pool UUID URL.
  * `connector_pool_name` - Parent pool name.

### Example

```hcl
data "eaa_data_source_agents" "all" {}

output "reachable_agents" {
  value = [for a in data.eaa_data_source_agents.all.agents : a.name if a.reach == 1]
}
```

---

## eaa_data_source_idps

Lists identity providers with their directories and groups.

### Attributes

* `idps` - List of IDPs:
  * `name` - IDP name.
  * `uuid_url` - UUID.
  * `directories` - List of directories:
    * `name` - Directory name.
    * `uuid` - UUID.
    * `groups` - List of groups:
      * `name` - Group name.
      * `uuid_url` - UUID.

### Example

```hcl
data "eaa_data_source_idps" "all" {}

output "idp_names" {
  value = [for idp in data.eaa_data_source_idps.all.idps : idp.name]
}
```

---

## eaa_data_source_directories

Lists all directories (user repositories) available in EAA.

### Attributes

* `directories` - List of directories:
  * `name` - Directory name.
  * `uuid_url` - UUID.
  * `service` - Directory service type. Common values: `1` = AD, `2` = LDAP, `6` = Cloud Directory.
  * `status` - Status code.
  * `directory_type` - Directory type code.
  * `user_count` - Number of users in the directory.
  * `group_count` - Number of groups in the directory.

### Example

```hcl
data "eaa_data_source_directories" "all" {}

output "cloud_directories" {
  value = [
    for d in data.eaa_data_source_directories.all.directories :
    d.name if d.service == 6
  ]
}

output "directory_summary" {
  value = {
    for d in data.eaa_data_source_directories.all.directories :
    d.name => {
      users  = d.user_count
      groups = d.group_count
      type   = d.service
    }
  }
}
```

---

## eaa_data_source_tls_cipher_suites

Lists TLS cipher suites available for a specific application.

### Arguments

* `app_uuid_url` - (Required) Application UUID.

### Attributes

* `cipher_suites` - List of suites:
  * `name` - Suite name.
  * `default` - Is default suite.
  * `selected` - Is currently selected.
  * `ssl_cipher` - Cipher string.
  * `ssl_protocols` - Protocol string.
  * `weak_cipher` - Is weak cipher.
* `cipher_suite_names` - List of suite name strings.
* `default_suite_name` - Default suite name.

### Example

```hcl
data "eaa_data_source_tls_cipher_suites" "app_tls" {
  app_uuid_url = eaa_application.web_app.uuid_url
}

output "available_suites" {
  value = data.eaa_data_source_tls_cipher_suites.app_tls.cipher_suite_names
}
```

---

## eaa_connector_pools

Lists all connector pools.

### Attributes

* `connector_pools` - List of pools:
  * `name` - Pool name.
  * `description` - Description.
  * `uuid_url` - UUID.
  * `package_type` - Package type.
  * `infra_type` - Infrastructure type.
  * `operating_mode` - Operating mode.
  * `created_at` - Creation timestamp.
  * `modified_at` - Last modified timestamp.
  * `is_enabled` - Whether the pool is enabled.
  * `send_alerts` - Whether alerts are enabled.
  * `apps` - List of associated applications.
  * `connectors` - List of connectors:
    * `name` - Connector name.
    * `uuid_url` - UUID.
    * `description` - Description.
    * `package` - Package type.
    * `state` - State code.
    * `status` - Status code.
    * `reach` - Reachability status.
    * `created_at` - Creation timestamp.
    * `modified_at` - Last modified timestamp.
    * `is_enabled` - Whether the connector is enabled.
    * `localization` - Localization.
    * `agent_infra_type` - Agent infrastructure type.
    * `geo_location` - Geographic location.
    * `last_checkin` - Last check-in timestamp.
    * `operating_mode` - Operating mode.
  * `registration_tokens` - List of registration tokens:
    * `uuid_url` - Token UUID.
    * `name` - Token name.
    * `max_use` - Maximum uses.
    * `connector_pool` - Parent pool.
    * `agents` - Associated agents.
    * `expires_at` - Expiration timestamp.
    * `image_url` - Image URL.
    * `token` - Token value.
    * `used_count` - Number of times used.
    * `token_suffix` - Token suffix.
    * `modified_at` - Last modified timestamp.
    * `generate_embedded_img` - Whether embedded image is generated.

### Example

```hcl
data "eaa_connector_pools" "all" {}

output "pool_names" {
  value = [for p in data.eaa_connector_pools.all.connector_pools : p.name]
}
```

---

## eaa_data_source_apps

Lists all applications.

### Attributes

* `apps` - List of applications:
  * `name` - App name.
  * `uuid_url` - UUID.

### Example

```hcl
data "eaa_data_source_apps" "all" {}

output "app_names" {
  value = [for a in data.eaa_data_source_apps.all.apps : a.name]
}
```
