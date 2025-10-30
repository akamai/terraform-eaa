# CORS Parameters

Configure Cross-Origin Resource Sharing (CORS) behavior.

* `allow_cors` - (Optional) Enable CORS support
* `cors_origin_list` - (Optional) Space-delimited list of allowed origins
* `cors_method_list` - (Optional) Space-delimited list of allowed HTTP methods
* `cors_header_list` - (Optional) Space-delimited list of allowed headers
* `cors_support_credential` - (Optional) Support credentials in CORS requests
* `cors_max_age` - (Optional) CORS preflight cache duration in seconds

## Example
```json
{
  "allow_cors": "true",
  "cors_origin_list": "https://app.example.com https://admin.example.com",
  "cors_method_list": "GET POST",
  "cors_header_list": "Authorization Content-Type",
  "cors_support_credential": "true",
  "cors_max_age": 600
}
```

Example file: [examples/custom_http_app.tf](../examples/custom_http_app.tf)
