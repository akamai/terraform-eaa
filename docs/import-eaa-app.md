# Import an EAA Application created outside of Terraform

Terraform can import existing infrastructure. This allows you to take either the subset of resources or all the resources, you have created by some other means and bring them under Terraform management.
Once imported, Terraform tracks the resource in your state file. You can then manage the imported resource like any other, updating its attributes and destroying it as part of a standard resource lifecycle.
The import block records that Terraform imported the resource and did not create it. After importing, you can optionally remove import blocks from your configuration or leave them as a record of the resource's origin.
Terraform v1.5.0 and later, use an import block to import eaa_application, that is created outside terraform, using application UUID.

## import eaa_application

To import a resource using import blocks:
Create a tf file with import block(s) for the resource(s).
```'sh
terraform {
    required_providers {
    eaa = {
      source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "1.0.0"
    }
  }
}
import {
  to = eaa_application.example_app_name
  id = "pDLkco4dS5KZ54AH70ISAw”
}
```
The above import block defines an import of the EAA application with the uuid_url "pDLkco4dS5KZ54AH70ISAw" into the eaa_application.example_app_name resource in the root module.

The import block has the following arguments:
* ```to``` - (Required) The instance address this resource will have in your state file.
* ```id``` - (Required) A string with the import ID of the resource.
