# Provider Configuration

A Terraform configuration is a complete document written in HCL (Hashicorp Configuration language) that tells Terraform how to manage a given collection of infrastructure.
Configuration files tell Terraform what plugins to install, what infrastructure to create, and what data to fetch.
The following sections describe how to define the configuration for the eaa provider.

## Required Providers

Each Terraform module must declare which providers it requires, so that Terraform can install and use them. Provider requirements are declared in a required_providers block.
A provider requirement consists of a local name, a source location, and a version constraint:

### Example Usage
```sh
terraform {
    required_providers {
    eaa = {
      source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "1.0.0"
    }
  }
}
```
The eaa terraform plugin is not released to the hashicorp provider repository yet. Hence, the "source" argument points to the location where the plugin binary is located locally.
If source is configured as "terraform.eaaprovider.dev/eaaprovider/eaa", version is configured as "1.0.0" and if the architecture is darwin_amd64, the eaa terraform binary will be located at ~/.terraform.d/plugins/terraform.eaaprovider.dev/eaaprovider/eaa/1.0.0/${PLUGIN_ARCH}

## Provider Configuration
Provider configurations belong in the root module of a Terraform configuration. A provider configuration is created using a provider block.
This provider should already be included in a required_providers block.

For configuring eaa provider, the name in the block header is the "eaa".

#### Usage
```sh
provider "eaa" {
  contractid       = "contract-id"
  accountswitchkey = "account-switch-key"
  edgerc           = ".edgerc"
}
```

#### Provider settings
* ```contractid``` - (Required) The Akamai contract identifier for your Enterprise Application Access product.
* ```accountswitchkey``` - (Optional) Runs the operation from another account.
* ```edgerc``` - (Optional) EAA TF plugin uses OpenAPI to configure the applications. API Client needs to be created from Akamai Enterprise Center, which contains client_secret, access_token & client_token required to authenticate Akamai EAA API. This setting contains the location of the .edgerc file. Follow the link for instructions on how to create [authentication credentials](https://techdocs.akamai.com/developer/docs/set-up-authentication-credentials
)

#### Environment variables
The authentication credentials can also be set using environment variables. The environment variables are:
https://techdocs.akamai.com/terraform/docs/environment-variables
