package eaaprovider

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	ErrDirectoryRollback = errors.New("directory create rollback triggered")
)

var dirServiceNameToInt = map[string]int{
	"AD":         1,
	"LDAP":       2,
	"OKTA":       3,
	"PINGONE":    4,
	"SAML":       5,
	"CLOUD":      6,
	"ONELOGIN":   7,
	"GOOGLE":     8,
	"AKAMAI":     9,
	"AKAMAI_MSP": 10,
	"LDS":        11,
	"SCIM":       12,
}

var dirServiceIntToName = map[int]string{
	1:  "AD",
	2:  "LDAP",
	3:  "OKTA",
	4:  "PINGONE",
	5:  "SAML",
	6:  "CLOUD",
	7:  "ONELOGIN",
	8:  "GOOGLE",
	9:  "AKAMAI",
	10: "AKAMAI_MSP",
	11: "LDS",
	12: "SCIM",
}

func resourceEaaDirectory() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceEaaDirectoryCreate,
		ReadContext:   resourceEaaDirectoryRead,
		UpdateContext: resourceEaaDirectoryUpdate,
		DeleteContext: resourceEaaDirectoryDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			// Required
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Directory name",
			},
			"service": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Directory type: AD, LDAP, OKTA, PINGONE, SAML, CLOUD, ONELOGIN, GOOGLE, AKAMAI, AKAMAI_MSP, LDS, SCIM",
				ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
					v, ok := val.(string)
					if !ok {
						errs = append(errs, fmt.Errorf("%q must be a string", key))
						return
					}
					if _, found := dirServiceNameToInt[v]; !found {
						errs = append(errs, fmt.Errorf("%q must be one of AD, LDAP, OKTA, PINGONE, SAML, CLOUD, ONELOGIN, GOOGLE, AKAMAI, AKAMAI_MSP, LDS, SCIM; got %q", key, v))
					}
					return
				},
			},

			// Optional — Directory config
			"description":                 {Type: schema.TypeString, Optional: true, Description: "Directory description"},
			"host":                        {Type: schema.TypeString, Optional: true, Description: "Directory server hostname or IP"},
			"port":                        {Type: schema.TypeInt, Optional: true, Computed: true, Description: "Directory server port"},
			"root_dn":                     {Type: schema.TypeString, Optional: true, Description: "Root distinguished name"},
			"admin_user":                  {Type: schema.TypeString, Optional: true, Description: "Admin bind username"},
			"admin_pwd":                   {Type: schema.TypeString, Optional: true, Sensitive: true, Description: "Admin bind password", DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool { return old != "" && new == "" }},
			"ssl":                         {Type: schema.TypeBool, Optional: true, Computed: true, Description: "Enable SSL connection"},
			"is_ssl_verification_enabled": {Type: schema.TypeBool, Optional: true, Computed: true, Description: "Enable SSL cert verification"},
			"is_leda_dir":                 {Type: schema.TypeBool, Optional: true, Description: "Whether this is a Leda-managed directory"},
			"mfa":                         {Type: schema.TypeString, Optional: true, Computed: true, Description: "MFA mode"},
			"logout_url":                  {Type: schema.TypeString, Optional: true, Description: "Logout URL"},

			// Agents (names, resolved to UUIDs internally)
			"agents": {
				Type:        schema.TypeSet,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Connector names (resolved to UUIDs)",
			},

			// Groups
			"groups": {
				Type:        schema.TypeSet,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Group names to search and assign",
			},

			// LDAP search/filter
			"user_base_dn":        {Type: schema.TypeString, Optional: true, Description: "Base DN for user searches"},
			"user_search_filter":  {Type: schema.TypeString, Optional: true, Computed: true, Description: "Filter for user searches"},
			"group_base_dn":       {Type: schema.TypeString, Optional: true, Description: "Base DN for group searches"},
			"group_search_filter": {Type: schema.TypeString, Optional: true, Computed: true, Description: "Filter for group searches"},
			"group_members":       {Type: schema.TypeString, Optional: true, Computed: true, Description: "Attribute for group members"},
			"group_name_attr":     {Type: schema.TypeString, Optional: true, Computed: true, Description: "Attribute for group name"},
			"group_token":         {Type: schema.TypeString, Optional: true, Computed: true, Description: "Attribute for primary group token"},
			"user_display_name":   {Type: schema.TypeString, Optional: true, Computed: true, Description: "Attribute for display name"},
			"user_email":          {Type: schema.TypeString, Optional: true, Computed: true, Description: "Attribute for email"},
			"user_fname":          {Type: schema.TypeString, Optional: true, Computed: true, Description: "Attribute for first name"},
			"user_lname":          {Type: schema.TypeString, Optional: true, Computed: true, Description: "Attribute for last name"},
			"user_phone_num":      {Type: schema.TypeString, Optional: true, Computed: true, Description: "Attribute for phone number"},
			"user_principal":      {Type: schema.TypeString, Optional: true, Computed: true, Description: "Attribute for user principal name"},
			"user_samaccountname": {Type: schema.TypeString, Optional: true, Computed: true, Description: "Attribute for sAMAccountName"},
			"user_upn":            {Type: schema.TypeString, Optional: true, Computed: true, Description: "Attribute for UPN"},
			"user_memberof":       {Type: schema.TypeString, Optional: true, Computed: true, Description: "Attribute for group membership"},
			"user_memberuid":      {Type: schema.TypeString, Optional: true, Computed: true, Description: "Attribute for member UID"},
			"ou_attr":             {Type: schema.TypeString, Optional: true, Description: "OU attribute"},
			"ou_filter":           {Type: schema.TypeString, Optional: true, Description: "OU filter"},

			// Set attributes (order-independent)
			"user_object_classes":  {Type: schema.TypeSet, Optional: true, Computed: true, Elem: &schema.Schema{Type: schema.TypeString}, Description: "Object classes for user entries"},
			"group_object_classes": {Type: schema.TypeSet, Optional: true, Computed: true, Elem: &schema.Schema{Type: schema.TypeString}, Description: "Object classes for group entries"},
			"ou_object_classes":    {Type: schema.TypeSet, Optional: true, Computed: true, Elem: &schema.Schema{Type: schema.TypeString}, Description: "Object classes for OU entries"},
			"host_aliases":         {Type: schema.TypeSet, Optional: true, Elem: &schema.Schema{Type: schema.TypeString}, Description: "Host aliases for directory server"},
			"domains":              {Type: schema.TypeSet, Optional: true, Elem: &schema.Schema{Type: schema.TypeString}, Description: "Associated domains"},

			// Additional settings
			"chase_referral":                 {Type: schema.TypeBool, Optional: true, Computed: true, Description: "Chase LDAP referrals"},
			"global_catalog":                 {Type: schema.TypeBool, Optional: true, Computed: true, Description: "Use AD Global Catalog"},
			"server_cert_validate":           {Type: schema.TypeBool, Optional: true, Computed: true, Description: "Validate server certificate"},
			"auth_request_signed":            {Type: schema.TypeBool, Optional: true, Computed: true, Description: "Sign auth requests"},
			"auth_response_encrypt":          {Type: schema.TypeBool, Optional: true, Computed: true, Description: "Encrypt auth responses"},
			"password_change_allow":          {Type: schema.TypeBool, Optional: true, Computed: true, Description: "Allow password changes"},
			"password_reset_allow":           {Type: schema.TypeBool, Optional: true, Computed: true, Description: "Allow password resets"},
			"password_policy_default":        {Type: schema.TypeString, Optional: true, Computed: true, Description: "Default password policy"},
			"password_expire_warn_threshold": {Type: schema.TypeInt, Optional: true, Computed: true, Description: "Days before expiry to warn"},
			"password_change_threshold":      {Type: schema.TypeInt, Optional: true, Computed: true, Description: "Password change threshold"},
			"password_complexity_message":    {Type: schema.TypeString, Optional: true, Computed: true, Description: "Custom complexity message"},
			"is_rate_limit_enabled":          {Type: schema.TypeBool, Optional: true, Computed: true, Description: "Enable rate limiting"},
			"rate_limit_time_interval":       {Type: schema.TypeInt, Optional: true, Computed: true, Description: "Rate limit interval (seconds)"},
			"rate_limit_query_count":         {Type: schema.TypeInt, Optional: true, Computed: true, Description: "Max queries per interval"},
			"scim_provider_id":               {Type: schema.TypeString, Optional: true, Description: "SCIM provider ID"},
			"company_id":                     {Type: schema.TypeString, Optional: true, Computed: true, Description: "Company identifier"},
			"source":                         {Type: schema.TypeString, Optional: true, Description: "Source identifier"},

			// Map attributes
			"attribute_map":   {Type: schema.TypeMap, Optional: true, Computed: true, Elem: &schema.Schema{Type: schema.TypeString}, Description: "Custom attribute mapping"},
			"password_filter": {Type: schema.TypeMap, Optional: true, Computed: true, Elem: &schema.Schema{Type: schema.TypeString}, Description: "Password filter rules"},

			// Computed
			"uuid_url":                  {Type: schema.TypeString, Computed: true, Description: "Unique identifier"},
			"created_at":                {Type: schema.TypeString, Computed: true, Description: "Creation timestamp"},
			"modified_at":               {Type: schema.TypeString, Computed: true, Description: "Last modification timestamp"},
			"localization":              {Type: schema.TypeString, Computed: true, Description: "Data center localization"},
			"directory_type":            {Type: schema.TypeInt, Computed: true, Description: "Directory type code"},
			"directory_status":          {Type: schema.TypeInt, Computed: true, Description: "Overall directory status code"},
			"directory_deployed_status": {Type: schema.TypeInt, Computed: true, Description: "Deployment lifecycle status"},
			"cname":                     {Type: schema.TypeString, Computed: true, Description: "Directory CNAME"},
			"dialin_sni":                {Type: schema.TypeString, Computed: true, Description: "Dial-in SNI hostname"},
			"sync_state":                {Type: schema.TypeInt, Computed: true, Description: "Sync state"},
			"sync_interval":             {Type: schema.TypeInt, Computed: true, Description: "Sync interval in seconds"},
			"last_sync":                 {Type: schema.TypeString, Computed: true, Description: "Last sync timestamp"},
			"user_count":                {Type: schema.TypeInt, Computed: true, Description: "Number of users"},
			"group_count":               {Type: schema.TypeInt, Computed: true, Description: "Number of groups"},
			"status":                    {Type: schema.TypeInt, Computed: true, Description: "Directory status"},
		},
	}
}

func rollbackDirectory(ctx context.Context, d *schema.ResourceData, ec *client.EaaClient, uuid string, originalErr error, tags []logging.Tag) diag.Diagnostics {
	logging.Warn(ctx, "rolling back directory creation", tags, map[string]any{"uuid": uuid, "error": originalErr.Error()})
	d.SetId("")
	deleteErr := client.DeleteDirectory(ctx, ec, uuid)
	if deleteErr != nil {
		logging.Error(ctx, "rollback delete failed", tags, map[string]any{"delete_error": deleteErr.Error()})
		return logging.DiagFromErr(
			fmt.Errorf("%w: original error: %v, rollback delete also failed: %v", ErrDirectoryRollback, originalErr, deleteErr),
			tags, "directory create failed and rollback also failed",
		)
	}
	return logging.DiagFromErr(originalErr, tags, "directory create failed (rolled back)")
}

func applyDirectoryConfigToBody(ctx context.Context, d *schema.ResourceData, ec *client.EaaClient, body *client.DirectoryFullResponse, tags []logging.Tag) error {
	if s, ok := d.Get("name").(string); ok {
		body.Name = s
	}
	if v, ok := d.GetOk("description"); ok {
		if s, ok := v.(string); ok {
			body.Description = s
		}
	}
	if v, ok := d.GetOk("host"); ok {
		if s, ok := v.(string); ok {
			body.Host = s
		}
	}
	if d.IsNewResource() || d.HasChange("port") {
		if p, ok := d.Get("port").(int); ok {
			body.Port = &p
		}
	}
	if v, ok := d.GetOk("root_dn"); ok {
		if s, ok := v.(string); ok {
			body.RootDN = s
		}
	}
	if v, ok := d.GetOk("admin_user"); ok {
		if s, ok := v.(string); ok {
			body.AdminUser = s
		}
	}
	if v, ok := d.GetOk("admin_pwd"); ok {
		if s, ok := v.(string); ok {
			body.AdminPwd = s
		}
	}
	if d.IsNewResource() || d.HasChange("ssl") {
		if b, ok := d.Get("ssl").(bool); ok {
			body.SSL = &b
		}
	}
	if d.IsNewResource() || d.HasChange("is_ssl_verification_enabled") {
		if b, ok := d.Get("is_ssl_verification_enabled").(bool); ok {
			body.IsSSLVerificationEnabled = &b
		}
	}
	if d.IsNewResource() || d.HasChange("is_leda_dir") {
		if b, ok := d.Get("is_leda_dir").(bool); ok {
			body.IsLedaDir = &b
		}
	}
	if v, ok := d.GetOk("mfa"); ok {
		if s, ok := v.(string); ok {
			body.MFA = s
		}
	}
	if v, ok := d.GetOk("logout_url"); ok {
		if s, ok := v.(string); ok {
			body.LogoutURL = s
		}
	}

	// LDAP fields
	stringFields := map[string]*string{
		"user_base_dn":                &body.UserBaseDN,
		"user_search_filter":          &body.UserSearchFilter,
		"group_base_dn":               &body.GroupBaseDN,
		"group_search_filter":         &body.GroupSearchFilter,
		"group_members":               &body.GroupMembers,
		"group_name_attr":             &body.GroupName,
		"group_token":                 &body.GroupToken,
		"user_display_name":           &body.UserDisplayName,
		"user_email":                  &body.UserEmail,
		"user_fname":                  &body.UserFname,
		"user_lname":                  &body.UserLname,
		"user_phone_num":              &body.UserPhoneNum,
		"user_principal":              &body.UserPrincipal,
		"user_samaccountname":         &body.UserSamaccountname,
		"user_upn":                    &body.UserUPN,
		"user_memberof":               &body.UserMemberof,
		"user_memberuid":              &body.UserMemberuid,
		"ou_attr":                     &body.OUAttr,
		"ou_filter":                   &body.OUFilter,
		"password_policy_default":     &body.PasswordPolicyDefault,
		"password_complexity_message": &body.PasswordComplexityMsg,
		"scim_provider_id":            &body.ScimProviderID,
		"company_id":                  &body.CompanyID,
		"source":                      &body.Source,
	}
	for key, target := range stringFields {
		if v, ok := d.GetOk(key); ok {
			if s, ok := v.(string); ok {
				*target = s
			}
		}
	}

	// Bool fields
	boolFields := map[string]**bool{
		"chase_referral":        &body.ChaseReferral,
		"global_catalog":        &body.GlobalCatalog,
		"server_cert_validate":  &body.ServerCertValidate,
		"auth_request_signed":   &body.AuthRequestSigned,
		"auth_response_encrypt": &body.AuthResponseEncrypt,
		"password_change_allow": &body.PasswordChangeAllow,
		"password_reset_allow":  &body.PasswordResetAllow,
		"is_rate_limit_enabled": &body.IsRateLimitEnabled,
	}
	for key, target := range boolFields {
		if d.IsNewResource() || d.HasChange(key) {
			if b, ok := d.Get(key).(bool); ok {
				*target = &b
			}
		}
	}

	// Int fields
	if d.IsNewResource() || d.HasChange("password_expire_warn_threshold") {
		if n, ok := d.Get("password_expire_warn_threshold").(int); ok {
			body.PasswordExpireWarn = &n
		}
	}
	if d.IsNewResource() || d.HasChange("password_change_threshold") {
		if n, ok := d.Get("password_change_threshold").(int); ok {
			body.PasswordChangeThreshold = &n
		}
	}
	if d.IsNewResource() || d.HasChange("rate_limit_time_interval") {
		if n, ok := d.Get("rate_limit_time_interval").(int); ok {
			body.RateLimitTimeInterval = &n
		}
	}
	if d.IsNewResource() || d.HasChange("rate_limit_query_count") {
		if n, ok := d.Get("rate_limit_query_count").(int); ok {
			body.RateLimitQueryCount = &n
		}
	}

	// Set attributes
	if v, ok := d.GetOk("user_object_classes"); ok {
		if s, ok := v.(*schema.Set); ok {
			body.UserObjectClasses = interfaceListToStringSlice(s.List())
		}
	}
	if v, ok := d.GetOk("group_object_classes"); ok {
		if s, ok := v.(*schema.Set); ok {
			body.GroupObjectClasses = interfaceListToStringSlice(s.List())
		}
	}
	if v, ok := d.GetOk("ou_object_classes"); ok {
		if s, ok := v.(*schema.Set); ok {
			body.OUObjectClasses = interfaceListToStringSlice(s.List())
		}
	}
	if v, ok := d.GetOk("host_aliases"); ok {
		if s, ok := v.(*schema.Set); ok {
			body.HostAliases = interfaceListToStringSlice(s.List())
		}
	}
	if v, ok := d.GetOk("domains"); ok {
		if s, ok := v.(*schema.Set); ok {
			body.Domains = interfaceListToStringSlice(s.List())
		}
	}

	// Map attributes
	if v, ok := d.GetOk("attribute_map"); ok {
		if m, ok := v.(map[string]interface{}); ok {
			body.AttributeMap = stringMapToInterfaceMap(m)
		}
	}
	if v, ok := d.GetOk("password_filter"); ok {
		if m, ok := v.(map[string]interface{}); ok {
			body.PasswordFilter = stringMapToInterfaceMap(m)
		}
	}

	// Resolve agents by name
	if v, ok := d.GetOk("agents"); ok {
		agentSet, ok := v.(*schema.Set)
		if !ok {
			return logging.Errorf(tags, "agents: unexpected type %T", v)
		}
		if agentSet.Len() > 0 {
			allAgents, agentErr := client.GetAgents(ctx, ec)
			if agentErr != nil {
				return logging.Wrapf(agentErr, tags, "failed to list agents for name resolution")
			}
			agentByName := make(map[string]client.Connector)
			for i := range allAgents {
				agentByName[allAgents[i].Name] = allAgents[i]
			}
			var resolvedAgents []client.Connector
			for _, item := range agentSet.List() {
				name, ok := item.(string)
				if !ok {
					return logging.Errorf(tags, "agents: expected string, got %T", item)
				}
				agent, found := agentByName[name]
				if !found {
					return logging.Errorf(tags, "agent '%s' not found", name)
				}
				resolvedAgents = append(resolvedAgents, agent)
			}
			body.Agents = resolvedAgents
		}
	}

	return nil
}

func resourceEaaDirectoryCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagDirectory, logging.TagCreate}
	logging.Info(ctx, "creating directory", tags)

	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	createReq := &client.DirectoryCreateRequest{}
	if s, ok := d.Get("name").(string); ok {
		createReq.Name = s
	}
	if v, ok := d.GetOk("description"); ok {
		if s, ok := v.(string); ok {
			createReq.Description = s
		}
	}
	if v, ok := d.GetOk("service"); ok {
		if s, ok := v.(string); ok {
			if i, found := dirServiceNameToInt[s]; found {
				createReq.Service = i
			}
		}
	}
	if v, ok := d.GetOk("is_leda_dir"); ok {
		if b, ok := v.(bool); ok {
			createReq.IsLedaDir = b
		}
	}

	createResp, err := client.CreateDirectory(ctx, eaaclient, createReq)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to create directory")
	}

	dirUUID := createResp.UUIDURL
	d.SetId(dirUUID)

	// GET current state, overlay config, PUT
	currentDir, err := client.GetDirectory(ctx, eaaclient, dirUUID)
	if err != nil {
		return rollbackDirectory(ctx, d, eaaclient, dirUUID, err, tags)
	}
	if applyErr := applyDirectoryConfigToBody(ctx, d, eaaclient, currentDir, tags); applyErr != nil {
		return rollbackDirectory(ctx, d, eaaclient, dirUUID, applyErr, tags)
	}
	_, err = client.UpdateDirectory(ctx, eaaclient, dirUUID, currentDir)
	if err != nil {
		return rollbackDirectory(ctx, d, eaaclient, dirUUID, err, tags)
	}

	// Deploy directory
	if deployErr := client.DeployDirectory(ctx, eaaclient, dirUUID); deployErr != nil {
		return rollbackDirectory(ctx, d, eaaclient, dirUUID, deployErr, tags)
	}

	// Verify directory
	if verifyErr := client.VerifyDirectory(ctx, eaaclient, dirUUID); verifyErr != nil {
		return rollbackDirectory(ctx, d, eaaclient, dirUUID, verifyErr, tags)
	}

	// Search and assign groups
	if v, ok := d.GetOk("groups"); ok {
		groupSet, ok := v.(*schema.Set)
		if !ok {
			return rollbackDirectory(ctx, d, eaaclient, dirUUID, fmt.Errorf("groups: unexpected type %T", v), tags)
		}
		for _, item := range groupSet.List() {
			groupName, ok := item.(string)
			if !ok {
				return rollbackDirectory(ctx, d, eaaclient, dirUUID, fmt.Errorf("groups: expected string, got %T", item), tags)
			}

			searchResult, searchErr := client.SearchDirectoryGroup(ctx, eaaclient, dirUUID, groupName)
			if searchErr != nil {
				return rollbackDirectory(ctx, d, eaaclient, dirUUID, searchErr, tags)
			}

			_, assignErr := client.AssignDirectoryGroup(ctx, eaaclient, dirUUID, searchResult)
			if assignErr != nil {
				return rollbackDirectory(ctx, d, eaaclient, dirUUID, assignErr, tags)
			}
		}

		// Verify groups are assigned
		_, getGroupsErr := client.GetDirectoryGroups(ctx, eaaclient, dirUUID)
		if getGroupsErr != nil {
			return rollbackDirectory(ctx, d, eaaclient, dirUUID, getGroupsErr, tags)
		}

		// Update directory again with group info
		updatedDir, getErr := client.GetDirectory(ctx, eaaclient, dirUUID)
		if getErr != nil {
			return rollbackDirectory(ctx, d, eaaclient, dirUUID, getErr, tags)
		}
		_, updateErr := client.UpdateDirectory(ctx, eaaclient, dirUUID, updatedDir)
		if updateErr != nil {
			return rollbackDirectory(ctx, d, eaaclient, dirUUID, updateErr, tags)
		}
	}

	// Sync
	if syncErr := client.SyncDirectory(ctx, eaaclient, dirUUID); syncErr != nil {
		return rollbackDirectory(ctx, d, eaaclient, dirUUID, syncErr, tags)
	}

	logging.Info(ctx, "directory created successfully", tags, map[string]any{"uuid": dirUUID})
	return resourceEaaDirectoryRead(ctx, d, m)
}

func resourceEaaDirectoryRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagDirectory, logging.TagRead}
	logging.Info(ctx, "reading directory", tags)

	id := d.Id()
	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	dirResp, err := client.GetDirectory(ctx, eaaclient, id)
	if err != nil {
		if errors.Is(err, client.ErrDirectoryNotFound) {
			logging.Warn(ctx, "directory not found, removing from state", tags, map[string]any{"uuid": id})
			d.SetId("")
			return nil
		}
		return logging.DiagFromErr(err, tags, "failed to read directory")
	}

	// Fetch assigned groups
	groups, groupErr := client.GetDirectoryGroups(ctx, eaaclient, id)
	if groupErr != nil {
		return logging.DiagFromErr(groupErr, tags, "failed to get directory groups")
	}

	attrs := make(map[string]interface{})
	attrs["name"] = dirResp.Name
	attrs["uuid_url"] = dirResp.UUIDURL
	attrs["description"] = dirResp.Description
	if name, ok := dirServiceIntToName[dirResp.Service]; ok {
		attrs["service"] = name
	} else {
		attrs["service"] = strconv.Itoa(dirResp.Service)
	}
	attrs["created_at"] = dirResp.CreatedAt
	attrs["modified_at"] = dirResp.ModifiedAt
	attrs["localization"] = dirResp.Localization
	attrs["directory_type"] = dirResp.DirectoryType
	attrs["directory_status"] = dirResp.DirectoryStatus
	attrs["directory_deployed_status"] = dirResp.DirectoryDeployedStatus
	attrs["cname"] = dirResp.CName
	attrs["dialin_sni"] = dirResp.DialinSNI
	attrs["sync_state"] = dirResp.SyncState
	attrs["sync_interval"] = dirResp.SyncInterval
	attrs["last_sync"] = dirResp.LastSync
	attrs["user_count"] = dirResp.UserCount
	attrs["group_count"] = dirResp.GroupCount
	attrs["status"] = dirResp.Status
	attrs["host"] = dirResp.Host
	if dirResp.Port != nil {
		attrs["port"] = *dirResp.Port
	}
	attrs["root_dn"] = dirResp.RootDN
	attrs["admin_user"] = dirResp.AdminUser
	if dirResp.SSL != nil {
		attrs["ssl"] = *dirResp.SSL
	}
	if dirResp.IsSSLVerificationEnabled != nil {
		attrs["is_ssl_verification_enabled"] = *dirResp.IsSSLVerificationEnabled
	}
	if dirResp.IsLedaDir != nil {
		attrs["is_leda_dir"] = *dirResp.IsLedaDir
	}
	attrs["mfa"] = dirResp.MFA
	attrs["logout_url"] = dirResp.LogoutURL
	if dirResp.ChaseReferral != nil {
		attrs["chase_referral"] = *dirResp.ChaseReferral
	}
	if dirResp.GlobalCatalog != nil {
		attrs["global_catalog"] = *dirResp.GlobalCatalog
	}
	if dirResp.ServerCertValidate != nil {
		attrs["server_cert_validate"] = *dirResp.ServerCertValidate
	}
	if dirResp.AuthRequestSigned != nil {
		attrs["auth_request_signed"] = *dirResp.AuthRequestSigned
	}
	if dirResp.AuthResponseEncrypt != nil {
		attrs["auth_response_encrypt"] = *dirResp.AuthResponseEncrypt
	}
	if dirResp.PasswordChangeAllow != nil {
		attrs["password_change_allow"] = *dirResp.PasswordChangeAllow
	}
	if dirResp.PasswordResetAllow != nil {
		attrs["password_reset_allow"] = *dirResp.PasswordResetAllow
	}
	attrs["password_policy_default"] = dirResp.PasswordPolicyDefault
	if dirResp.PasswordExpireWarn != nil {
		attrs["password_expire_warn_threshold"] = *dirResp.PasswordExpireWarn
	}
	if dirResp.PasswordChangeThreshold != nil {
		attrs["password_change_threshold"] = *dirResp.PasswordChangeThreshold
	}
	attrs["password_complexity_message"] = dirResp.PasswordComplexityMsg
	if dirResp.IsRateLimitEnabled != nil {
		attrs["is_rate_limit_enabled"] = *dirResp.IsRateLimitEnabled
	}
	if dirResp.RateLimitTimeInterval != nil {
		attrs["rate_limit_time_interval"] = *dirResp.RateLimitTimeInterval
	}
	if dirResp.RateLimitQueryCount != nil {
		attrs["rate_limit_query_count"] = *dirResp.RateLimitQueryCount
	}
	attrs["scim_provider_id"] = dirResp.ScimProviderID
	attrs["company_id"] = dirResp.CompanyID
	attrs["source"] = dirResp.Source
	attrs["user_base_dn"] = dirResp.UserBaseDN
	attrs["user_search_filter"] = dirResp.UserSearchFilter
	attrs["group_base_dn"] = dirResp.GroupBaseDN
	attrs["group_search_filter"] = dirResp.GroupSearchFilter
	attrs["group_members"] = dirResp.GroupMembers
	attrs["group_name_attr"] = dirResp.GroupName
	attrs["group_token"] = dirResp.GroupToken
	attrs["user_display_name"] = dirResp.UserDisplayName
	attrs["user_email"] = dirResp.UserEmail
	attrs["user_fname"] = dirResp.UserFname
	attrs["user_lname"] = dirResp.UserLname
	attrs["user_phone_num"] = dirResp.UserPhoneNum
	attrs["user_principal"] = dirResp.UserPrincipal
	attrs["user_samaccountname"] = dirResp.UserSamaccountname
	attrs["user_upn"] = dirResp.UserUPN
	attrs["user_memberof"] = dirResp.UserMemberof
	attrs["user_memberuid"] = dirResp.UserMemberuid
	attrs["ou_attr"] = dirResp.OUAttr
	attrs["ou_filter"] = dirResp.OUFilter

	if err := client.SetAttrs(d, attrs); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set directory attributes")
	}

	// Set TypeSet attributes
	if dirResp.UserObjectClasses != nil {
		if err := d.Set("user_object_classes", dirResp.UserObjectClasses); err != nil {
			return logging.DiagFromErr(err, tags, "failed to set user_object_classes")
		}
	}
	if dirResp.GroupObjectClasses != nil {
		if err := d.Set("group_object_classes", dirResp.GroupObjectClasses); err != nil {
			return logging.DiagFromErr(err, tags, "failed to set group_object_classes")
		}
	}
	if dirResp.OUObjectClasses != nil {
		if err := d.Set("ou_object_classes", dirResp.OUObjectClasses); err != nil {
			return logging.DiagFromErr(err, tags, "failed to set ou_object_classes")
		}
	}
	hostAliases := dirResp.HostAliases
	if hostAliases == nil {
		hostAliases = []string{}
	}
	if err := d.Set("host_aliases", hostAliases); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set host_aliases")
	}
	domains := dirResp.Domains
	if domains == nil {
		domains = []string{}
	}
	if err := d.Set("domains", domains); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set domains")
	}

	// Set map attributes
	attrMap := map[string]string{}
	if dirResp.AttributeMap != nil {
		attrMap = interfaceMapToStringMap(dirResp.AttributeMap)
	}
	if err := d.Set("attribute_map", attrMap); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set attribute_map")
	}
	pwdFilter := map[string]string{}
	if dirResp.PasswordFilter != nil {
		pwdFilter = interfaceMapToStringMap(dirResp.PasswordFilter)
	}
	if err := d.Set("password_filter", pwdFilter); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set password_filter")
	}

	// Reverse-resolve agents UUIDs to names
	if len(dirResp.Agents) > 0 {
		agentsList, agentErr := client.GetAgents(ctx, eaaclient)
		if agentErr != nil {
			return logging.DiagFromErr(agentErr, tags, "failed to list agents for name resolution")
		}
		agentNames := make([]string, 0, len(dirResp.Agents))
		for i := range dirResp.Agents {
			for j := range agentsList {
				if agentsList[j].UUIDURL == dirResp.Agents[i].UUIDURL {
					agentNames = append(agentNames, agentsList[j].Name)
					break
				}
			}
		}
		if err := d.Set("agents", agentNames); err != nil {
			return logging.DiagFromErr(err, tags, "failed to set agents")
		}
	} else {
		if err := d.Set("agents", []string{}); err != nil {
			return logging.DiagFromErr(err, tags, "failed to set agents")
		}
	}

	// Set groups from fetched group entries
	groupNames := make([]string, 0, len(groups))
	for _, g := range groups {
		if g.Name != "" {
			groupNames = append(groupNames, g.Name)
		}
	}
	if err := d.Set("groups", groupNames); err != nil {
		return logging.DiagFromErr(err, tags, "failed to set groups")
	}

	logging.Info(ctx, "directory read successfully", tags)
	return nil
}

func resourceEaaDirectoryUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagDirectory, logging.TagUpdate}
	logging.Info(ctx, "updating directory", tags)

	id := d.Id()
	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	// GET current state
	currentDir, err := client.GetDirectory(ctx, eaaclient, id)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to read directory for update")
	}

	// Overlay config and PUT
	if applyErr := applyDirectoryConfigToBody(ctx, d, eaaclient, currentDir, tags); applyErr != nil {
		return logging.DiagFromErr(applyErr, tags, "failed to resolve directory config for update")
	}

	_, err = client.UpdateDirectory(ctx, eaaclient, id, currentDir)
	if err != nil {
		readDiags := resourceEaaDirectoryRead(ctx, d, m)
		updateDiags := logging.DiagFromErr(err, tags, "failed to update directory")
		return append(updateDiags, readDiags...)
	}

	// Diff groups
	if d.HasChange("groups") {
		// Sync before group changes
		if syncErr := client.SyncDirectory(ctx, eaaclient, id); syncErr != nil {
			return logging.DiagFromErr(syncErr, tags, "failed to sync directory before group changes")
		}

		oldRaw, newRaw := d.GetChange("groups")
		oldSet, ok := oldRaw.(*schema.Set)
		if !ok {
			return logging.DiagFromErr(fmt.Errorf("old groups is not a *schema.Set"), tags, "unexpected type for groups")
		}
		newSet, ok := newRaw.(*schema.Set)
		if !ok {
			return logging.DiagFromErr(fmt.Errorf("new groups is not a *schema.Set"), tags, "unexpected type for groups")
		}

		removed := oldSet.Difference(newSet)
		added := newSet.Difference(oldSet)

		// Remove groups
		if removed.Len() > 0 {
			currentGroups, getErr := client.GetDirectoryGroups(ctx, eaaclient, id)
			if getErr != nil {
				return logging.DiagFromErr(getErr, tags, "failed to get groups for diff")
			}

			removeNames := make(map[string]bool)
			for _, v := range removed.List() {
				if name, ok := v.(string); ok {
					removeNames[name] = true
				}
			}

			for _, g := range currentGroups {
				if removeNames[g.Name] {
					if removeErr := client.RemoveDirectoryGroup(ctx, eaaclient, id, g.UUIDURL); removeErr != nil {
						return logging.DiagFromErr(removeErr, tags, "failed to remove group")
					}
				}
			}
		}

		// Add groups
		for _, v := range added.List() {
			groupName, ok := v.(string)
			if !ok {
				return logging.DiagFromErr(fmt.Errorf("groups: expected string, got %T", v), tags, "unexpected type in groups set")
			}

			searchResult, searchErr := client.SearchDirectoryGroup(ctx, eaaclient, id, groupName)
			if searchErr != nil {
				return logging.DiagFromErr(searchErr, tags, "failed to search group for assignment")
			}

			_, assignErr := client.AssignDirectoryGroup(ctx, eaaclient, id, searchResult)
			if assignErr != nil {
				return logging.DiagFromErr(assignErr, tags, "failed to assign group")
			}
		}

		// Sync after group changes
		if syncErr := client.SyncDirectory(ctx, eaaclient, id); syncErr != nil {
			return logging.DiagFromErr(syncErr, tags, "failed to sync directory after group changes")
		}
	}

	logging.Info(ctx, "directory updated successfully", tags)
	return resourceEaaDirectoryRead(ctx, d, m)
}

func resourceEaaDirectoryDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tags := []logging.Tag{logging.TagProvider, logging.TagDirectory, logging.TagDelete}
	logging.Info(ctx, "deleting directory", tags)

	id := d.Id()
	eaaclient, err := Client(m)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to get client")
	}

	err = client.DeleteDirectory(ctx, eaaclient, id)
	if err != nil {
		return logging.DiagFromErr(err, tags, "failed to delete directory")
	}

	d.SetId("")
	logging.Info(ctx, "directory deleted successfully", tags)
	return nil
}
