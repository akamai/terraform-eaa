# Enterprise Connectivity Parameters

Configure connection behavior between EAA and your enterprise servers.

* `app_server_read_timeout` - (Optional) Application server read timeout in seconds (minimum 60). Default 300
* `idle_close_time_seconds` - (Optional) Idle connection close time in seconds (maximum 1800). Default 300
* `proxy_buffer_size_kb` - (Optional) Proxy buffer size in KB (4-256, multiple of 4). Default 4

## Example
```json
{
  "app_server_read_timeout": 300,
  "idle_close_time_seconds": 300,
  "proxy_buffer_size_kb": 16
}
```

Example file: [examples/custom_http_app.tf](../examples/custom_http_app.tf)
