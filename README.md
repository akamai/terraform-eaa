# EAA Provider for Terraform

## Table of contents<!-- omit in toc -->

- [Introduction](#introduction)
- [Key features](#key-features)
- [Installation](#installation)
- [Examples](#examples)
  - [Create a new application](#create-a-new-application-using-terraform)
  - [Import all applications into Terraform](#import-applications-created-outside-terraform)
- [Scope and Limitations](#scope-and-limitations)
- [Troubleshooting and Support](#troubleshooting-and-support)
  - [Self-troubleshooting](#self-troubleshooting)
  - [Support](#support)
- [References](#references)

## Introduction

[Enterprise Application Access (EAA)](https://www.akamai.com/us/en/products/security/enterprise-application-access.jsp) comes with a full suite of APIs. 
Yet you need to write scripts or use [Postman](https://developer.akamai.com/authenticate-with-postman) to be able to interact with the service.

With EAA Terraform provider, you can run some common operations directly from the command line, no coding required.

## Key features

- Application
  - Create/modify an application
  - Import operations
  - Certain advanced settings

## Installation

See [install.md](docs/install.md)


## Examples

## Create a new application using Terraform:

1. Export the API client `.edgerc` to a location where `.tf` files are also located.

2. `.tf` must contain the following sections:
    - `required_providers` [required_providers](docs/eaa-provider-configuration.md)
    - `"eaa" provider details`
    - `resource config for your application`[app_config](docs/create-an-app.md)

    * Refer to the [Examples](examples), for sample tf files.

3. To create multiple apps using Terraform, either multiple `.tf` files (for example, one for each app) could be created or one `.tf` file could contain configurations of all apps.

4. Run the following terraform commands:
```sh
  terraform init
  terraform plan
  terraform apply
```
5. All the app configuration is now pushed to EAA and the app deployments would start.

6. If you are deploying multiple apps at once, the deployment could take a while. It’s recommended to deploy in batches.

## Import applications created outside Terraform

EAA Terraform provider comes with an import tool that can be used to import all or a subset of applications that are created outside Terraform and manage them using Terraform infrastructure.
The import tool relies on the `.edgerc` configuration to access the tenant details and prompts for a comma-separated application names.

```'sh
./bin/import-config
terraform init
terraform plan -generate-config-out=generated.tf /* Terraform can generate code for the resources you define in import blocks that do not already exist in your configuration. */
cat import_existing_apps.tf
terraform plan
terraform apply
```

## Scope and Limitations

### The EAA Terraform provider currently supports:

- Create and deploy an application 
- Update the application
- Apps with Akamai domain and custom domain 
- Self signed certificate for custom domain
- Uploaded certicate for custom domain
- Assigning pops to the application
- Assigning App categories to the application
- Assigning connectors to the application
- Assigning IDP to the application
- Assigning directories to the application 
- Assigning groups to the application
- Enabling Access service
- Creating access control rule(s) to block or deny access to an application, based on User/Group criteria
- updating G2O
- subset of advanced_settings
- updating connectors, IDPs, directories and groups assigned to application
- data sources for app_categories, pops, agents, idps, directories and groups
- Supports only Mac darwin_amd64

### The EAA custom plugin currently does not support
- all of advanced_settings

## Troubleshooting and Support

### Self-troubleshooting
To enable verbose logging of Terraform operations, set `export TF_LOG=[Info/Error/Debug/Warn]` prior to running any Terraform commands.
The messages are printed on the console.

### Support

EAA Terraform provider is provided as-is and it is not supported by Akamai Support.
To report any issue, feature request or bug, please open a new issue into the [GitHub Issues page](https://github.com/akamai/cli-eaa/issues)

We are strongly encouraging developer to create a pull request.

## References:
For more information about using EAA in Akamai Control Center, refer to [Enterprise Application Access](https://techdocs.akamai.com/eaa/docs)

To learn the basics of Terraform using this provider, follow the hands-on [get started tutorials](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/infrastructure-as-code?utm_medium=WEB_IO&in=terraform%2Faws-get-started&utm_content=DOCS&utm_source=WEBSITE&utm_offer=ARTICLE_PAGE).

[Managing infrstructure with Terraform](https://developer.hashicorp.com/terraform/tutorials/cli/plan)

[Enterprise Application Access API](https://techdocs.akamai.com/eaa-api/reference/api)