# Akamai EAA Terraform provider: installation and configuration instructions<!-- omit in toc -->

## Table of contents<!-- omit in toc -->

- [Installation](#installation)
  - [Pre-requisites](#pre-requisites)
  - [EAA Terraform Provider](#eaa-terraform-provider)
- [Configuration](#configuration)

## Installation

### Pre-requisites

Terraform could be run either locally or inside a Docker container.

[Download Terraform](https://www.terraform.io/downloads.html)
[Install Terraform](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli)

### EAA Terraform Provider

The following are the instructions to run the provider locally.
We currently support only Mac darwin_amd64 platform.

1. Download EAA Terraform provider source code
2. Build the provider binary. Navigate to the folder eaa_terraform and run the make command
```sh
  cd eaa_terraform
  make
```

And voilà!

The targets of the Makefile are,
   * /bin/terraform-provider-eaa
   * /bin/import-config

## Configuration

In order to work, the EAA provider will look for an `.edgerc` configuration file stored in your home directory or your prefered location \
where the configuration `.tf` files are also present.

To create a {OPEN} API user, follow [these instructions](https://developer.akamai.com/legacy/introduction/Prov_Creds.html).
Make sure the API user has READ-WRITE permission to *Enterprise Application Access*.

To create a legacy API key and secret from, connect to Akamai Control Center.
- use Enterprise Application Access in the left menu
- go to **System** > **Settings** and
- then click **Generate new API Key** in the **API** section of the page

The `.edgerc` file should look like:

```INI
[default]

; Akamai {OPEN} API credentials
host = akaa-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx.luna.akamaiapis.net
client_token = akab-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx
client_secret = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
access_token = akab-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx

```
