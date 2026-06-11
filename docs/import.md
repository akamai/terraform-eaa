# Import

## Import Block

Import an existing EAA application by UUID (Terraform >= 1.5):

```hcl
import {
  to = eaa_application.my_app
  id = "pDLkco4dS5KZ54AH70ISAw"
}
```

Then generate the configuration:

```sh
terraform plan -generate-config-out=generated.tf
```

## Bulk Import Tool

Import multiple applications at once using the bundled tool:

```sh
./bin/import-config           # prompts for comma-separated app names
terraform init
terraform plan -generate-config-out=generated.tf
terraform plan
```

**Review `terraform plan` output carefully before applying.** Lines starting with `~` indicate in-place modifications to existing applications. Only proceed with `terraform apply` after confirming the changes are expected.
