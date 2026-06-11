# Troubleshooting

## Enable Logging

```sh
export TF_LOG=DEBUG    # levels: TRACE, DEBUG, INFO, WARN, ERROR
terraform apply
```

Write to file:

```sh
export TF_LOG=DEBUG
export TF_LOG_PATH=./terraform.log
terraform apply
```

## Log Tag Format

All log lines use the format `[SOURCE][RESOURCE][OPERATION]`. Filter with `grep` to isolate specific operations.

```sh
# all application API calls
grep '\[API\]\[APP\]' terraform.log

# connector pool creation (provider + API layers)
grep '\[CONN_POOL\]\[CREATE\]' terraform.log

# all validation errors
grep '\[VALIDATE\]' terraform.log

# everything at the API layer
grep '\[API\]' terraform.log
```

## Source Tags

| Tag | Layer | Description |
|---|---|---|
| `API` | HTTP client | Outbound EAA API requests and responses |
| `PROVIDER` | Terraform provider | Resource CRUD, state mapping, plan diffs |
| `CONFIG` | Validation | Schema and configuration validation |

## Resource Tags

| Tag | Resource |
|---|---|
| `APP` | `eaa_application` |
| `CONNECTOR` | `eaa_connector` |
| `CONN_POOL` | `eaa_connector_pool` |
| `IDP` | Identity provider |
| `CERT` | Certificate |
| `APP_SVC` | Application service (ACL rules) |
| `AGENT` | Connector agent |
| `DIRECTORY` | IDP directory |
| `APP_BUNDLE` | Application bundle |
| `CIPHER` | TLS cipher suite |
| `POP_TRAFFIC` | PoP traffic / regions |

## Operation Tags

| Tag | Meaning |
|---|---|
| `CREATE` | Resource creation |
| `READ` | Resource read / refresh |
| `UPDATE` | Resource update |
| `DELETE` | Resource deletion |
| `VALIDATE` | Input validation |
| `ASSIGN` | Association (connector→pool, IDP→app, directory→app) |
| `DEPLOY` | Application deployment |
| `LIST` | List/enumerate resources |
| `MARSHAL` | JSON serialization |
| `AUTH` | Authentication configuration |

## All Tag Combinations

**API layer (`[API][*][*]`):**

| Tag | Description |
|---|---|
| `[API][APP][CREATE]` | Create application |
| `[API][APP][READ]` | Read application |
| `[API][APP][UPDATE]` | Update application |
| `[API][APP][DELETE]` | Delete application |
| `[API][APP][DEPLOY]` | Deploy application |
| `[API][APP][LIST]` | List applications |
| `[API][APP][AUTH]` | Configure app authentication |
| `[API][APP_SVC][CREATE]` | Create ACL service |
| `[API][APP_SVC][READ]` | Read ACL service |
| `[API][APP_SVC][UPDATE]` | Update ACL service |
| `[API][APP_SVC][DELETE]` | Delete ACL service |
| `[API][CONNECTOR][CREATE]` | Create connector |
| `[API][CONNECTOR][UPDATE]` | Update connector |
| `[API][CONNECTOR][DELETE]` | Delete connector |
| `[API][CONNECTOR][VALIDATE]` | Validate connector |
| `[API][CONN_POOL][CREATE]` | Create connector pool |
| `[API][CONN_POOL][READ]` | Read connector pool |
| `[API][CONN_POOL][UPDATE]` | Update connector pool |
| `[API][CONN_POOL][DELETE]` | Delete connector pool |
| `[API][CONN_POOL][LIST]` | List connector pools |
| `[API][CONN_POOL][ASSIGN]` | Assign connectors/apps to pool |
| `[API][CONN_POOL][VALIDATE]` | Validate pool configuration |
| `[API][AGENT][READ]` | Read agent |
| `[API][AGENT][LIST]` | List agents |
| `[API][AGENT][ASSIGN]` | Assign agent |
| `[API][IDP][READ]` | Read IDP |
| `[API][IDP][LIST]` | List IDPs |
| `[API][IDP][ASSIGN]` | Assign IDP to app |
| `[API][DIRECTORY][READ]` | Read directory |
| `[API][DIRECTORY][ASSIGN]` | Assign directory to app |
| `[API][CERT][CREATE]` | Upload certificate |
| `[API][CERT][READ]` | Read certificate |
| `[API][CIPHER][READ]` | Read cipher suites |
| `[API][APP_BUNDLE][READ]` | Read app bundle |
| `[API][APP_BUNDLE][LIST]` | List app bundles |
| `[API][POP_TRAFFIC][READ]` | Read PoP traffic |
| `[API][POP_TRAFFIC][LIST]` | List PoP traffic |

**Provider layer (`[PROVIDER][*][*]`):**

| Tag | Description |
|---|---|
| `[PROVIDER][APP][CREATE]` | Application resource create |
| `[PROVIDER][APP][READ]` | Application resource read |
| `[PROVIDER][APP][UPDATE]` | Application resource update |
| `[PROVIDER][APP][DELETE]` | Application resource delete |
| `[PROVIDER][APP][VALIDATE]` | Application input validation |
| `[PROVIDER][CONNECTOR][CREATE]` | Connector resource create |
| `[PROVIDER][CONNECTOR][READ]` | Connector resource read |
| `[PROVIDER][CONNECTOR][UPDATE]` | Connector resource update |
| `[PROVIDER][CONNECTOR][DELETE]` | Connector resource delete |
| `[PROVIDER][CONN_POOL][CREATE]` | Pool resource create |
| `[PROVIDER][CONN_POOL][READ]` | Pool resource read |
| `[PROVIDER][CONN_POOL][UPDATE]` | Pool resource update |
| `[PROVIDER][CONN_POOL][DELETE]` | Pool resource delete |
| `[PROVIDER][AGENT][READ]` | Agent data source read |
| `[PROVIDER][IDP][READ]` | IDP data source read |
| `[PROVIDER][CIPHER][READ]` | Cipher data source read |
| `[PROVIDER][POP_TRAFFIC][READ]` | PoP data source read |
