# Miscellaneous Parameters

Various application behavior settings.

* `custom_headers` - (Optional) Custom headers to insert and forward
* `hidden_app` - (Optional) Hide application from user interface
* `offload_onpremise_traffic` - (Optional) Offload on-premise traffic
* `logging_enabled` - (Optional) Enable application logging
* `saas_enabled` - (Optional) Enable SaaS mode
* `segmentation_policy_enable` - (Optional) Enable segmentation policy
* `sticky_agent` - (Optional) Route requests to same connector

## Example
```json
{
  "custom_headers": {
    "insert": {"X-Frame-Options": "DENY"},
    "forward": ["X-Trace-Id"]
  },
  "hidden_app": "false",
  "offload_onpremise_traffic": "false",
  "logging_enabled": "true",
  "saas_enabled": "false",
  "segmentation_policy_enable": "false",
  "sticky_agent": "false"
}
```

Example file: [examples/custom_http_app.tf](../examples/custom_http_app.tf)
