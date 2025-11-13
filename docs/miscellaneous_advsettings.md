# Miscellaneous Parameters

Various application behavior settings.

* `custom_headers` - (Optional) Custom headers to insert and forward
* `hidden_app` - (Optional) Hide application from user interface
* `offload_onpremise_traffic` - (Optional) Offload on-premise traffic
* `logging_enabled` - (Optional) Enable application logging
* `saas_enabled` - (Optional) Enable SaaS mode
* `segmentation_policy_enable` - (Optional) Enable segmentation policy
* `sticky_agent` - (Optional) Route requests to same connector

## Examples

See the following example files for usage:

* [examples/enterprise_valid.tf](../examples/enterprise_valid.tf) - Comprehensive enterprise application with all miscellaneous parameters including `sticky_agent`, `hidden_app`, `logging_enabled`, `saas_enabled`, and `offload_onpremise_traffic`
* [examples/custom_http_app.tf](../examples/custom_http_app.tf) - Custom HTTP application demonstrating `custom_headers`, `sticky_agent`, `hidden_app`, `logging_enabled`, `offload_onpremise_traffic`, and `saas_enabled`
