package client

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"time"

	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var validRuleTypes = map[string]bool{
	ACCESS_RULE_SETTING_URL:      true,
	ACCESS_RULE_SETTING_GROUP:    true,
	ACCESS_RULE_SETTING_USER:     true,
	ACCESS_RULE_SETTING_CLIENTIP: true,
	ACCESS_RULE_SETTING_COUNTRY:  true,
	ACCESS_RULE_SETTING_TIME:     true,
	ACCESS_RULE_SETTING_METHOD:   true,
}

type ACLService struct {
	Name     string       `json:"name,omitempty"`
	Status   string       `json:"status,omitempty"`
	ACLRules []AccessRule `json:"settings,omitempty"`
}

type AccessRuleRequest struct {
	CreatedAt      time.Time    `json:"created_at"`
	ModifiedAt     time.Time    `json:"modified_at"`
	Description    *string      `json:"description"`
	AuthzRule      *string      `json:"authz_rule"`
	Name           string       `json:"name"`
	PartnerUUID    string       `json:"partner_uuid"`
	PartnerUUIDURL string       `json:"partner_uuid_url"`
	Service        string       `json:"service"`
	TenantUUID     string       `json:"tenant_uuid"`
	Settings       []ACLSetting `json:"settings"`
	Action         int          `json:"action"`
	RuleType       int          `json:"rule_type"`
	Status         int          `json:"status"`
	GlobalRule     bool         `json:"global_rule"`
	MergeGlobal    bool         `json:"merge_global"`
}

type AppServiceData struct {
	UUIDURL string     `json:"uuid_url,omitempty"`
	Service AppService `json:"service,omitempty"`
	Status  int        `json:"status,omitempty"`
}

type AppServicesResponse struct {
	AppServices []AppServiceData `json:"objects,omitempty"`
}

type ACLSetting struct {
	Operator string `json:"operator,omitempty"`
	Type     string `json:"type,omitempty"`
	Value    string `json:"value,omitempty"`
}

func (r ACLSetting) Validate() error {
	// Validate operator
	switch r.Operator {
	case OPERATOR_IS, OPERATOR_IS_NOT:
		// Valid operator
	default:
		return fmt.Errorf("invalid rule operator: %s", r.Operator)
	}

	// Validate type
	if !validRuleTypes[r.Type] {
		return fmt.Errorf("invalid rule type: %s", r.Type)
	}
	return nil
}

type AccessRule struct {
	Name     string       `json:"name,omitempty"`
	UUID_URL string       `json:"uuid_url,omitempty"`
	Settings []ACLSetting `json:"settings,omitempty"`
	Status   int          `json:"status,omitempty"`
}

func (rule AccessRule) CreateAccessRule(ctx context.Context, ec *EaaClient, serviceUUIDURL string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagAppService, logging.TagCreate}
	logging.Info(ctx, "CreateAccessRule", tags)

	if serviceUUIDURL == "" {
		logging.Warn(ctx, "create Access Rule failed: empty uuid_url", tags)
		return logging.Errorf(tags, "create rule failed: empty uuid_url")
	}
	arReq := AccessRuleRequest{
		Action:      RULE_ACTION_DENY,
		AuthzRule:   nil,
		CreatedAt:   time.Now(),
		Description: nil,
		GlobalRule:  false,
		MergeGlobal: true,
		ModifiedAt:  time.Now(),
		Name:        rule.Name,
		RuleType:    RULE_TYPE_ACCESS_CTRL,
		Service:     serviceUUIDURL,
		Settings:    rule.Settings,
		Status:      rule.Status,
	}
	apiURL := fmt.Sprintf("%s://%s/%s/%s/rules", URL_SCHEME, ec.Host, SERVICES_URL, serviceUUIDURL)
	createRuleResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", arReq, nil, false)

	if err != nil {
		logging.Warn(ctx, "create rule failed", tags, map[string]any{"error": err})
		return err
	}

	if createRuleResp.StatusCode != http.StatusOK {
		desc := FormatErrorDescription(createRuleResp)
		logging.Warn(ctx, "create Access Rule failed", tags, map[string]any{"status": createRuleResp.StatusCode, "description": desc})
		return logging.Errorf(tags, "create rule failed: %s", desc)
	}
	logging.Info(ctx, "create Access Rule succeeded", tags, map[string]any{"name": arReq.Name})
	return nil
}

func (rule AccessRule) DeleteAccessRule(ctx context.Context, ec *EaaClient, serviceUUIDURL string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagAppService, logging.TagDelete}
	if rule.UUID_URL == "" || serviceUUIDURL == "" {
		logging.Warn(ctx, "delete Access Rule failed: empty uuid_url", tags)
		return logging.Errorf(tags, "delete rule failed: empty uuid_url")
	}
	apiURL := fmt.Sprintf("%s://%s/%s/%s/rules/%s", URL_SCHEME, ec.Host, SERVICES_URL, serviceUUIDURL, rule.UUID_URL)
	deleteResp, err := ec.SendAPIRequest(ctx, apiURL, http.MethodDelete, nil, nil, false)
	if err != nil {
		return err
	}

	if deleteResp.StatusCode < http.StatusOK || deleteResp.StatusCode >= http.StatusMultipleChoices {
		return logging.Errorf(tags, "delete rule failed")
	}
	return nil
}

func (rule AccessRule) ModifyAccessRule(ctx context.Context, ec *EaaClient, serviceUUIDURL string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagAppService, logging.TagUpdate}
	logging.Info(ctx, "ModifyAccessRule", tags)

	if rule.UUID_URL == "" || serviceUUIDURL == "" {
		logging.Warn(ctx, "modify Access Rule failed: empty uuid_url", tags)
		return logging.Errorf(tags, "modify rule failed: empty uuid_url")
	}
	arReq := AccessRuleRequest{
		Action:      RULE_ACTION_DENY,
		AuthzRule:   nil,
		Description: nil,
		GlobalRule:  false,
		MergeGlobal: true,
		ModifiedAt:  time.Now(),
		Name:        rule.Name,
		RuleType:    RULE_TYPE_ACCESS_CTRL,
		Service:     serviceUUIDURL,
		Settings:    rule.Settings,
		Status:      rule.Status,
	}
	apiURL := fmt.Sprintf("%s://%s/%s/%s/rules/%s", URL_SCHEME, ec.Host, SERVICES_URL, serviceUUIDURL, rule.UUID_URL)
	createRuleResp, err := ec.SendAPIRequest(ctx, apiURL, "PUT", arReq, nil, false)

	if err != nil {
		logging.Warn(ctx, "modify rule failed", tags, map[string]any{"error": err})
		return err
	}

	if createRuleResp.StatusCode < http.StatusOK || createRuleResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(createRuleResp)
		logging.Warn(ctx, "modify Access Rule failed", tags, map[string]any{"status": createRuleResp.StatusCode, "description": desc})
		return logging.Errorf(tags, "modify rule failed: %s", desc)
	}
	logging.Info(ctx, "modify Access Rule succeeded", tags, map[string]any{"name": arReq.Name})
	return nil
}

func (rule AccessRule) IsEqual(otherRule AccessRule) bool {
	if rule.Status != otherRule.Status {
		return false
	}

	if len(rule.Settings) != len(otherRule.Settings) {
		return false
	}

	for i, setting := range rule.Settings {
		if setting != otherRule.Settings[i] {
			return false
		}
	}

	return true
}

type AppService struct {
	Name        string `json:"name,omitempty"`
	Status      string `json:"status,omitempty"`
	UUIDURL     string `json:"uuid_url,omitempty"`
	ServiceType int    `json:"service_type,omitempty"`
}

func (appService AppService) EnableService(ctx context.Context, ec *EaaClient) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagAppService, logging.TagUpdate}
	logging.Info(ctx, "EnableService", tags)

	if appService.UUIDURL == "" {
		logging.Warn(ctx, "enabling access service failed: empty uuid_url", tags)
		return logging.Errorf(tags, "enable service failed: empty uuid_url")
	}
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, SERVICES_URL, appService.UUIDURL)

	getResp, err := ec.SendAPIRequest(ctx, apiURL, "PUT", &appService, nil, false)
	if err != nil {
		return logging.Wrapf(err, tags, "failed to enable app service")
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(getResp)
		return logging.Errorf(tags, "enable service failed: %s", desc)
	}
	return nil
}

func (appService AppService) CreateAppServiceStruct(ctx context.Context, ec *EaaClient) ([]interface{}, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagAppService, logging.TagRead}
	if appService.UUIDURL == "" {
		logging.Warn(ctx, "CreateAppServiceStruct failed: empty uuid_url", tags)
		return nil, logging.Errorf(tags, "creating appservice struct failed: empty uuid_url")
	}

	response, err := GetAccessControlRules(ctx, ec, appService.UUIDURL)
	if err != nil {
		logging.Warn(ctx, "get access control rules failed", tags, map[string]any{"error": err})
		return nil, err
	}

	if len(response.ACLRules) == 0 {
		logging.Warn(ctx, "no ACL rules found in response", tags)
		return nil, nil
	}

	appSvc := make(map[string]interface{})
	appSvc["service_type"] = "access"
	appSvc["status"] = appService.Status

	var accessRules []map[string]interface{}
	var ruleStatus string
	for _, aclRule := range response.ACLRules {

		if aclRule.Status == ADMIN_STATE_ENABLED {
			ruleStatus = RULE_ON
		} else {
			ruleStatus = RULE_OFF
		}
		rule := map[string]interface{}{
			"name":   aclRule.Name,
			"status": ruleStatus,
		}

		var rules []map[string]interface{}

		for _, aclSetting := range aclRule.Settings {
			ruleMap := map[string]interface{}{
				"operator": aclSetting.Operator,
				"type":     aclSetting.Type,
				"value":    aclSetting.Value,
			}
			rules = append(rules, ruleMap)
		}
		sort.SliceStable(rules, func(i, j int) bool {
			typeI, okI := rules[i]["type"].(string)
			typeJ, okJ := rules[j]["type"].(string)
			switch {
			case !okI && !okJ:
				return false
			case !okI:
				return false
			case !okJ:
				return true
			default:
				return typeI < typeJ
			}
		})
		rule["rule"] = rules
		accessRules = append(accessRules, rule)

	}

	sort.SliceStable(accessRules, func(i, j int) bool {
		nameI, okI := accessRules[i]["name"].(string)
		nameJ, okJ := accessRules[j]["name"].(string)
		switch {
		case !okI && !okJ:
			return false
		case !okI:
			return false
		case !okJ:
			return true
		default:
			return nameI < nameJ
		}
	})

	appSvc["access_rule"] = accessRules
	return []interface{}{appSvc}, nil
}

func GetACLService(ctx context.Context, ec *EaaClient, appUUIDURL string) (*AppService, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagAppService, logging.TagRead}
	logging.Info(ctx, "GetACLService", tags)

	if appUUIDURL == "" {
		logging.Warn(ctx, "get access service failed: empty uuid_url", tags)
		return nil, logging.Errorf(tags, "enable service failed: empty uuid_url")
	}
	apiURL := fmt.Sprintf("%s://%s/%s/%s/services", URL_SCHEME, ec.Host, APPS_URL, appUUIDURL)
	asResponse := AppServicesResponse{}

	getResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &asResponse, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "failed to get app services")
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(getResp)
		return nil, logging.Errorf(tags, "get app services failed: %s", desc)
	}

	for _, ac := range asResponse.AppServices {
		if ac.Service.ServiceType == SERVICE_TYPE_ACCESS_CTRL {
			return &ac.Service, nil
		}
	}

	return nil, logging.Errorf(tags, "get app services failed")
}

func ExtractACLService(ctx context.Context, d *schema.ResourceData, ec *EaaClient) (*ACLService, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagAppService, logging.TagRead}
	var aclAccessRules []AccessRule
	var aclSrv ACLService

	// Read services list from ResourceData
	servicesRaw, ok := d.Get("service").([]interface{})
	if !ok {
		logging.Info(ctx, "invalid service configuration", tags)
		return nil, logging.Errorf(tags, "invalid service configuration")
	}

	// Iterate through each service
	for _, svcRaw := range servicesRaw {
		appSvc, ok := svcRaw.(map[string]interface{})
		if !ok {
			logging.Info(ctx, "invalid service configuration", tags)
			return nil, logging.Errorf(tags, "invalid service configuration")
		}

		serviceType, ok := appSvc["service_type"].(string)
		if !ok {
			logging.Info(ctx, "invalid or missing service_type", tags)
			return nil, logging.Errorf(tags, "invalid or missing service_type")
		}

		if serviceType != string(ServiceTypeAccessCtrl) {
			continue
		}

		serviceStatus, ok := appSvc["status"].(string)
		if !ok {
			logging.Info(ctx, "invalid or missing service status", tags)
			return nil, logging.Errorf(tags, "invalid or missing service status")
		}
		aclSrv.Status = serviceStatus

		// Extract access rules
		accessRulesRaw, ok := appSvc["access_rule"].([]interface{})
		if !ok {
			logging.Info(ctx, "invalid access_rule list", tags)
			return nil, logging.Errorf(tags, "invalid access_rule list")
		}

		for _, accessRuleRaw := range accessRulesRaw {
			accessRule, ok := accessRuleRaw.(map[string]interface{})
			if !ok {
				logging.Info(ctx, "invalid access_rule configuration", tags)
				return nil, logging.Errorf(tags, "invalid access_rule configuration")
			}

			var rules []ACLSetting
			rulesRaw, ok := accessRule["rule"].([]interface{})
			if !ok {
				logging.Info(ctx, "invalid rule list type", tags)
				return nil, logging.Errorf(tags, "invalid rule list")
			}

			for _, ruleRaw := range rulesRaw {
				ruleMap, ruleMapOK := ruleRaw.(map[string]interface{})
				if !ruleMapOK {
					logging.Info(ctx, "invalid rule configuration", tags)
					return nil, logging.Errorf(tags, "invalid rule configuration")
				}

				ruleOperator, ruleOperatorOK := ruleMap["operator"].(string)
				if !ruleOperatorOK {
					logging.Info(ctx, "invalid or missing rule operator", tags)
					return nil, logging.Errorf(tags, "invalid or missing rule operator")
				}

				ruleType, ruleTypeOK := ruleMap["type"].(string)
				if !ruleTypeOK {
					logging.Info(ctx, "invalid or missing rule type", tags)
					return nil, logging.Errorf(tags, "invalid or missing rule type")
				}

				value, valueOK := ruleMap["value"].(string)
				if !valueOK {
					logging.Info(ctx, "invalid or missing rule value", tags)
					return nil, logging.Errorf(tags, "invalid or missing rule value")
				}
				rule := ACLSetting{
					Operator: ruleOperator,
					Type:     ruleType,
					Value:    value,
				}

				if err := rule.Validate(); err != nil {
					return nil, logging.Errorf(tags, "invalid rule configuration")
				}

				rules = append(rules, rule)
			}

			name, ok := accessRule["name"].(string)
			if !ok {
				logging.Info(ctx, "invalid or missing access_rule name", tags)
				return nil, logging.Errorf(tags, "invalid or missing access_rule name")
			}

			status, ok := accessRule["status"].(string)
			ruleStatus := ADMIN_STATE_DISABLED
			if !ok || (status != RULE_ON && status != RULE_OFF) {
				status = RULE_OFF
			}
			if status == RULE_ON {
				ruleStatus = ADMIN_STATE_ENABLED
			}

			aclAccessRules = append(aclAccessRules, AccessRule{
				Name:     name,
				Settings: rules,
				Status:   ruleStatus,
			})
		}
	}
	aclSrv.ACLRules = aclAccessRules
	return &aclSrv, nil
}

type ACLRulesResponse struct {
	ACLRules []AccessRule `json:"objects,omitempty"`
}

func GetAccessControlRules(ctx context.Context, ec *EaaClient, serviceUUIDURL string) (*ACLRulesResponse, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagAppService, logging.TagRead}
	logging.Info(ctx, "GetAccessControlRules", tags)

	if serviceUUIDURL == "" {
		logging.Warn(ctx, "get access control rules failed: empty uuid_url", tags)
		return nil, logging.Errorf(tags, "enable service failed: empty uuid_url")
	}
	apiURL := fmt.Sprintf("%s://%s/%s/%s/rules", URL_SCHEME, ec.Host, SERVICES_URL, serviceUUIDURL)
	asResponse := ACLRulesResponse{}

	getResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &asResponse, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "failed to get access control rules")
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(getResp)
		return nil, logging.Errorf(tags, "get app services failed: %s", desc)
	}

	return &asResponse, nil
}
