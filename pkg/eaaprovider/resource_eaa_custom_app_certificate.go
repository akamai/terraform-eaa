package eaaprovider

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceEaaCustomAppCertificate() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceEaaCustomAppCertificateCreate,
		ReadContext:   resourceEaaCustomAppCertificateRead,
		UpdateContext: resourceEaaCustomAppCertificateUpdate,
		DeleteContext: resourceEaaCustomAppCertificateDelete,
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
				Optional: true,
				DiffSuppressFunc: func(k, oldValue, newValue string, d *schema.ResourceData) bool {
					return strings.TrimSpace(oldValue) == strings.TrimSpace(newValue)
				},
			},
			"private_key": {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
			},
			"password": {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
				Default:   "",
			},
			"private_key_sha256": {
				Type:     schema.TypeString,
				Computed: true,
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

func associatedObjectSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"name": {
			Type:     schema.TypeString,
			Computed: true,
		},
		"uuid_url": {
			Type:     schema.TypeString,
			Computed: true,
		},
		"status": {
			Type:     schema.TypeInt,
			Computed: true,
		},
	}
}

func flattenAssociatedObjects(objects []client.AssociatedObject) []map[string]interface{} {
	result := make([]map[string]interface{}, len(objects))
	for i, obj := range objects {
		result[i] = map[string]interface{}{
			"name":     obj.Name,
			"uuid_url": obj.UUIDURL,
			"status":   obj.Status,
		}
	}
	return result
}

func resourceEaaCustomAppCertificateCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagCert, logging.TagCreate}
	logging.Info(ctx, "creating custom app certificate", tags)

	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	certRaw, ok := d.GetOk("cert")
	if !ok {
		return logging.DiagErrorf(tags, "'cert' is required for creating a custom app certificate")
	}
	certStr, ok := certRaw.(string)
	if !ok || certStr == "" {
		return logging.DiagErrorf(tags, "'cert' must be a non-empty string")
	}

	privateKeyRaw, ok := d.GetOk("private_key")
	if !ok {
		return logging.DiagErrorf(tags, "'private_key' is required for creating a custom app certificate")
	}
	privateKeyStr, ok := privateKeyRaw.(string)
	if !ok || privateKeyStr == "" {
		return logging.DiagErrorf(tags, "'private_key' must be a non-empty string")
	}

	nameStr, ok := d.Get("name").(string)
	if !ok {
		return logging.DiagErrorf(tags, "'name' must be a string")
	}

	passwordStr, ok := d.Get("password").(string)
	if !ok {
		return logging.DiagErrorf(tags, "'password' must be a string")
	}

	req := &client.CreateAppCertRequest{
		CertType:   client.CERT_TYPE_APP,
		Name:       nameStr,
		Cert:       certStr,
		PrivateKey: privateKeyStr,
		Password:   passwordStr,
	}

	certResp, err := client.CreateAppCertificate(ctx, eaaclient, req)
	if err != nil {
		return logging.DiagFromErr(err, tags, "create custom app certificate failed")
	}

	d.SetId(certResp.UUIDURL)

	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(privateKeyStr)))
	if err := d.Set("private_key_sha256", hash); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set private_key_sha256")
	}

	logging.Info(ctx, "custom app certificate created successfully", tags)
	return resourceEaaCustomAppCertificateRead(ctx, d, m)
}

func resourceEaaCustomAppCertificateRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagCert, logging.TagRead}
	logging.Info(ctx, "reading custom app certificate", tags)

	id := d.Id()
	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	certResp, err := client.GetCertificateExpanded(ctx, eaaclient, id)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to read custom app certificate")
	}

	if certResp.CertType != client.CERT_TYPE_APP {
		return logging.DiagErrorf(tags, "certificate %s is not a custom app certificate (cert_type=%d, expected=%d)", id, certResp.CertType, client.CERT_TYPE_APP)
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
		return logging.DiagFromErr(err, tags, "failed to set custom app certificate attributes")
	}

	logging.Info(ctx, "custom app certificate read successfully", tags)
	return nil
}

func resourceEaaCustomAppCertificateUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagCert, logging.TagUpdate}
	logging.Info(ctx, "updating custom app certificate", tags)

	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	id := d.Id()

	certRaw, ok := d.GetOk("cert")
	if !ok {
		return logging.DiagErrorf(tags, "'cert' is required for updating a custom app certificate")
	}
	certStr, ok := certRaw.(string)
	if !ok || certStr == "" {
		return logging.DiagErrorf(tags, "'cert' must be a non-empty string")
	}

	privateKeyRaw, ok := d.GetOk("private_key")
	if !ok {
		return logging.DiagErrorf(tags, "'private_key' is required for updating a custom app certificate")
	}
	privateKeyStr, ok := privateKeyRaw.(string)
	if !ok || privateKeyStr == "" {
		return logging.DiagErrorf(tags, "'private_key' must be a non-empty string")
	}

	nameStr, ok := d.Get("name").(string)
	if !ok {
		return logging.DiagErrorf(tags, "'name' must be a string")
	}

	passwordStr, ok := d.Get("password").(string)
	if !ok {
		return logging.DiagErrorf(tags, "'password' must be a string")
	}

	req := &client.UpdateAppCertRequest{
		UUIDURL:    id,
		CertType:   client.CERT_TYPE_APP,
		Name:       nameStr,
		Cert:       certStr,
		PrivateKey: privateKeyStr,
		Password:   passwordStr,
	}

	_, err = client.UpdateAppCertificate(ctx, eaaclient, id, req)
	if err != nil {
		return logging.DiagFromErr(err, tags, "update custom app certificate failed")
	}

	var warningDiags diag.Diagnostics

	associated, assocErr := client.GetCertificateAssociated(ctx, eaaclient, id, nameStr, client.CERT_TYPE_APP)
	if assocErr != nil {
		logging.Warn(ctx, "failed to check certificate association, checking associated resources", tags, map[string]any{"error": assocErr.Error()})
		warningDiags = append(warningDiags, buildRedeployWarnings(ctx, eaaclient, id, tags)...)
	} else {
		if associated {
			if deployErr := client.DeployCertificate(ctx, eaaclient, id); deployErr != nil {
				logging.Warn(ctx, "certificate deploy failed, checking associated resources", tags)
				warningDiags = append(warningDiags, buildRedeployWarnings(ctx, eaaclient, id, tags)...)
			}
		} else {
			warningDiags = append(warningDiags, buildRedeployWarnings(ctx, eaaclient, id, tags)...)
		}
	}

	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(privateKeyStr)))
	if err := d.Set("private_key_sha256", hash); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set private_key_sha256")
	}

	logging.Info(ctx, "custom app certificate updated successfully", tags)
	readDiags := resourceEaaCustomAppCertificateRead(ctx, d, m)
	return append(warningDiags, readDiags...)
}

func buildRedeployWarnings(ctx context.Context, ec *client.EaaClient, certUUIDURL string, tags []logging.Tag) diag.Diagnostics {
	certResp, err := client.GetCertificateExpanded(ctx, ec, certUUIDURL)
	if err != nil {
		logging.Warn(ctx, "failed to read certificate for redeploy warning", tags, map[string]any{"error": err.Error()})
		return nil
	}

	var diags diag.Diagnostics
	if len(certResp.Apps) > 0 {
		names := make([]string, len(certResp.Apps))
		for i, app := range certResp.Apps {
			names[i] = app.Name
		}
		diags = append(diags, logging.DiagWarningf(tags, "The following applications need to be re-deployed for the new certificate to take effect: %v", names)...)
	}
	if len(certResp.IDPs) > 0 {
		names := make([]string, len(certResp.IDPs))
		for i, idp := range certResp.IDPs {
			names[i] = idp.Name
		}
		diags = append(diags, logging.DiagWarningf(tags, "The following IDPs need to be re-deployed for the new certificate to take effect: %v", names)...)
	}
	return diags
}

func resourceEaaCustomAppCertificateDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagCert, logging.TagDelete}
	logging.Info(ctx, "deleting custom app certificate", tags)

	id := d.Id()
	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	if err := client.DeleteCertificate(ctx, eaaclient, id); err != nil {
		return logging.DiagFromErr(err, tags, "failed to delete custom app certificate")
	}

	d.SetId("")
	logging.Info(ctx, "custom app certificate deleted successfully", tags)
	return nil
}
