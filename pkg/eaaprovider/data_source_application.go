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

var (
	ErrAppNotFound      = errors.New("application not found")
	ErrAppNameAmbiguous = errors.New("application name matches more than one application")
)

// dataSourceApplication exposes a single application, looked up by name or uuid_url,
// with the same attributes as the eaa_application resource.
func dataSourceApplication() *schema.Resource {
	s := datasourceSchemaFromResourceSchema(resourceEaaApplication().Schema)

	s["name"] = &schema.Schema{
		Type:         schema.TypeString,
		Optional:     true,
		Computed:     true,
		ExactlyOneOf: []string{"name", "uuid_url"},
		Description:  "Name of the application to look up. Must match exactly one application",
	}
	s["uuid_url"] = &schema.Schema{
		Type:         schema.TypeString,
		Optional:     true,
		Computed:     true,
		ExactlyOneOf: []string{"name", "uuid_url"},
		Description:  "UUID URL of the application to look up",
	}

	return &schema.Resource{
		ReadContext: dataSourceApplicationRead,
		Description: "Reads a single EAA application by name or uuid_url",
		Schema:      s,
	}
}

// datasourceSchemaFromResourceSchema returns a computed-only deep copy of a resource
// schema, so the data source exposes the same attributes. The resource schema is not modified.
func datasourceSchemaFromResourceSchema(rs map[string]*schema.Schema) map[string]*schema.Schema {
	ds := make(map[string]*schema.Schema, len(rs))
	for k, v := range rs {
		ds[k] = datasourceSchemaField(v, true)
	}
	return ds
}

// datasourceSchemaField copies the type information of a field and drops everything
// that only applies to configurable attributes (validation, defaults, diff handling, ...).
// Elem schemas of lists, sets and maps must only have a type, so they are not computed.
func datasourceSchemaField(rs *schema.Schema, computed bool) *schema.Schema {
	ds := &schema.Schema{
		Type:        rs.Type,
		Computed:    computed,
		Set:         rs.Set,
		Sensitive:   rs.Sensitive,
		Description: rs.Description,
		Elem:        rs.Elem,
	}
	switch elem := rs.Elem.(type) {
	case *schema.Resource:
		ds.Elem = &schema.Resource{Schema: datasourceSchemaFromResourceSchema(elem.SchemaMap())}
	case *schema.Schema:
		ds.Elem = datasourceSchemaField(elem, false)
	}
	return ds
}

func dataSourceApplicationRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagApp, logging.TagRead}
	logging.Info(ctx, "reading application data source", tags)

	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	uuidURL, _ := d.Get("uuid_url").(string) //nolint:errcheck // empty when looked up by name
	if uuidURL == "" {
		name, _ := d.Get("name").(string) //nolint:errcheck // ExactlyOneOf guarantees name is set
		uuidURL, err = resolveAppUUIDByName(ctx, eaaclient, name)
		if err != nil {
			return logging.DiagFromErr(err, tags, "failed to look up application by name")
		}
	}

	appResp, diags := readApplication(ctx, d, eaaclient, uuidURL)
	if diags.HasError() {
		return diags
	}

	// The read leaves out server-computed advanced settings (as for an import);
	// a data source exposes them so they can be referenced.
	advSettings, _ := d.Get("advanced_settings").(map[string]interface{}) //nolint:errcheck // nil when unset
	if advSettings == nil {
		advSettings = map[string]interface{}{}
	}
	for k, v := range serverComputedAdvancedSettings(appResp) {
		if v != "" {
			advSettings[k] = v
		}
	}
	if err := d.Set("advanced_settings", advSettings); err != nil {
		return append(diags, logging.DiagFromErr(err, tags, "failed to set advanced_settings")...)
	}

	d.SetId(uuidURL)

	logging.Info(ctx, "application data source read successfully", tags)
	return diags
}

// resolveAppUUIDByName returns the uuid_url of the application with exactly the given name.
func resolveAppUUIDByName(ctx context.Context, eaaclient *client.EaaClient, name string) (string, error) {
	apps, err := client.GetApps(ctx, eaaclient)
	if err != nil {
		return "", err
	}

	var matches []string
	for _, app := range apps {
		if app.Name == name {
			matches = append(matches, app.UUIDURL)
		}
	}

	switch len(matches) {
	case 0:
		return "", fmt.Errorf("%w: %q", ErrAppNotFound, name)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("%w: %q matches uuid_urls %s", ErrAppNameAmbiguous, name, strings.Join(matches, ", "))
	}
}
