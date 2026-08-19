package eaaprovider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceEaaCACertificate() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceEaaCACertificateCreate,
		ReadContext:   resourceEaaCACertificateRead,
		UpdateContext: resourceEaaCACertificateUpdate,
		DeleteContext: resourceEaaCACertificateDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"cert": {
				Type:     schema.TypeString,
				Required: true,
				DiffSuppressFunc: func(k, oldValue, newValue string, d *schema.ResourceData) bool {
					return strings.TrimSpace(oldValue) == strings.TrimSpace(newValue)
				},
			},
			"password": {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
				Default:   "",
			},
			"uuid_url": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"cn": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"subject": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"issuer": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"issued_at": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"expired_at": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"days_left": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"cert_file_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"status": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"app_count": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"dir_count": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"cert_type": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"created_at": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"modified_at": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"apps": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: associatedObjectSchema(),
				},
			},
			"idps": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: associatedObjectSchema(),
				},
			},
			"cert_idps": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: associatedObjectSchema(),
				},
			},
			"client_cert_idps": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: associatedObjectSchema(),
				},
			},
			"saml_cert_idps": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: associatedObjectSchema(),
				},
			},
			"saml_custom_sign_cert_idps": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: associatedObjectSchema(),
				},
			},
		},
	}
}

func resourceEaaCACertificateCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagCert, logging.TagCreate}
	logging.Info(ctx, "creating CA certificate", tags)

	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	name, ok := d.Get("name").(string)
	if !ok {
		return logging.DiagErrorf(tags, "'name' must be a string")
	}

	certContent, ok := d.Get("cert").(string)
	if !ok {
		return logging.DiagErrorf(tags, "'cert' must be a string")
	}

	password, ok := d.Get("password").(string)
	if !ok {
		return logging.DiagErrorf(tags, "'password' must be a string")
	}

	certResp, err := client.CreateCACertificate(ctx, eaaclient, name, certContent, password)
	if err != nil {
		return logging.DiagFromErr(err, tags, "create CA certificate failed")
	}

	d.SetId(certResp.UUIDURL)

	if certResp.CertFile != nil {
		if err := d.Set("cert_file_name", *certResp.CertFile); err != nil {
			return logging.DiagFromErr(err, tags, "failed to set cert_file_name")
		}
	}

	logging.Info(ctx, "CA certificate created successfully", tags)
	return resourceEaaCACertificateRead(ctx, d, m)
}

func resourceEaaCACertificateRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagCert, logging.TagRead}
	logging.Info(ctx, "reading CA certificate", tags)

	id := d.Id()
	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	certResp, err := client.GetCertificateExpanded(ctx, eaaclient, id)
	if err != nil {
		if errors.Is(err, client.ErrCertNotFound) {
			logging.Warn(ctx, "certificate not found, removing from state", tags, map[string]any{"id": id})
			d.SetId("")
			return nil
		}
		return logging.DiagFromErr(err, tags, "failed to read CA certificate")
	}

	if certResp.CertType != client.CERT_TYPE_CA {
		return logging.DiagErrorf(tags, "certificate %s is not a CA certificate (cert_type=%d, expected=%d)", id, certResp.CertType, client.CERT_TYPE_CA)
	}

	var certFileName string
	if certResp.CertFile != nil {
		certFileName = *certResp.CertFile
	} else if v, ok := d.Get("cert_file_name").(string); ok {
		certFileName = v
	}

	attrs := map[string]interface{}{
		"name":                       certResp.Name,
		"uuid_url":                   certResp.UUIDURL,
		"cert":                       certResp.Cert,
		"cn":                         certResp.CN,
		"subject":                    certResp.Subject,
		"issuer":                     certResp.Issuer,
		"issued_at":                  certResp.IssuedAt,
		"expired_at":                 certResp.ExpiredAt,
		"days_left":                  fmt.Sprintf("%d", certResp.DaysLeft),
		"cert_file_name":             certFileName,
		"status":                     fmt.Sprintf("%d", certResp.Status),
		"app_count":                  fmt.Sprintf("%d", certResp.AppCount),
		"dir_count":                  fmt.Sprintf("%d", certResp.DirCount),
		"cert_type":                  fmt.Sprintf("%d", certResp.CertType),
		"created_at":                 certResp.CreatedAt,
		"modified_at":                certResp.ModifiedAt,
		"apps":                       flattenAssociatedObjects(certResp.Apps),
		"idps":                       flattenAssociatedObjects(certResp.IDPs),
		"cert_idps":                  flattenAssociatedObjects(certResp.CertIDPs),
		"client_cert_idps":           flattenAssociatedObjects(certResp.ClientCertIDPs),
		"saml_cert_idps":             flattenAssociatedObjects(certResp.SAMLCertIDPs),
		"saml_custom_sign_cert_idps": flattenAssociatedObjects(certResp.SAMLCustomSignCertIDPs),
	}

	if err := client.SetAttrs(d, attrs); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set CA certificate attributes")
	}

	logging.Info(ctx, "CA certificate read successfully", tags)
	return nil
}

func resourceEaaCACertificateUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagCert, logging.TagUpdate}
	logging.Info(ctx, "updating CA certificate", tags)

	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	id := d.Id()

	name, ok := d.Get("name").(string)
	if !ok {
		return logging.DiagErrorf(tags, "'name' must be a string")
	}

	certContent, ok := d.Get("cert").(string)
	if !ok {
		return logging.DiagErrorf(tags, "'cert' must be a string")
	}

	password, ok := d.Get("password").(string)
	if !ok {
		return logging.DiagErrorf(tags, "'password' must be a string")
	}

	if err := client.UpdateCACertificate(ctx, eaaclient, id, name, certContent, password); err != nil {
		return logging.DiagFromErr(err, tags, "update CA certificate failed")
	}

	logging.Info(ctx, "CA certificate updated successfully", tags)
	return resourceEaaCACertificateRead(ctx, d, m)
}

func resourceEaaCACertificateDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagCert, logging.TagDelete}
	logging.Info(ctx, "deleting CA certificate", tags)

	id := d.Id()
	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	if err := client.DeleteCertificate(ctx, eaaclient, id); err != nil {
		return logging.DiagFromErr(err, tags, "failed to delete CA certificate")
	}

	d.SetId("")
	logging.Info(ctx, "CA certificate deleted successfully", tags)
	return nil
}
