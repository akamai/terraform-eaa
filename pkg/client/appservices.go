package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	ErrAppServicesGet = errors.New("get app services failed")
	ErrEnableService  = errors.New("enable service failed")
	ErrRuleCreate     = errors.New("create rule failed")
	ErrRuleModify     = errors.New("modify rule failed")
	ErrRuleDelete     = errors.New("delete rule failed")
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
	ec.Logger.Info("CreateAccessRule")
	if serviceUUIDURL == "" {
		ec.Logger.Error("create Access Rule failed. empty uuid_url")
		return ErrRuleCreate
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
	createRuleResp, err := ec.SendAPIRequest(apiURL, "POST", arReq, nil, false)

	if err != nil {
		ec.Logger.Error("create rule failed", "error", err)
		return err
	}

	if createRuleResp.StatusCode != http.StatusOK {
		desc := FormatErrorDescription(createRuleResp)
		createErrMsg := fmt.Errorf("%w: %s", ErrRuleCreate, desc)

		ec.Logger.Error("create Access Rule failed", "status", createRuleResp.StatusCode, "description", desc)
		return createErrMsg
	}
	ec.Logger.Info("create Access Rule succeeded.", "name", arReq.Name)
	return nil
}

func (rule AccessRule) DeleteAccessRule(ctx context.Context, ec *EaaClient, serviceUUIDURL string) error {
	if rule.UUID_URL == "" || serviceUUIDURL == "" {
		ec.Logger.Error("delete Access Rule failed. empty uuid_url")
		return ErrRuleDelete
	}
	apiURL := fmt.Sprintf("%s://%s/%s/%s/rules/%s", URL_SCHEME, ec.Host, SERVICES_URL, serviceUUIDURL, rule.UUID_URL)
	deleteResp, err := ec.SendAPIRequest(apiURL, http.MethodDelete, nil, nil, false)
	if err != nil {
		return err
	}

	if deleteResp.StatusCode < http.StatusOK || deleteResp.StatusCode >= http.StatusMultipleChoices {
		return ErrRuleDelete
	}
	return nil
}

func (rule AccessRule) ModifyAccessRule(ctx context.Context, ec *EaaClient, serviceUUIDURL string) error {
	ec.Logger.Info("ModifyAccessRule")
	if rule.UUID_URL == "" || serviceUUIDURL == "" {
		ec.Logger.Error("modify Access Rule failed. empty uuid_url")
		return ErrRuleModify
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
	createRuleResp, err := ec.SendAPIRequest(apiURL, "PUT", arReq, nil, false)

	if err != nil {
		ec.Logger.Error("modify rule failed", "error", err)
		return err
	}

	if createRuleResp.StatusCode < http.StatusOK || createRuleResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(createRuleResp)
		createErrMsg := fmt.Errorf("%w: %s", ErrRuleModify, desc)

		ec.Logger.Error("modify Access Rule failed", "status", createRuleResp.StatusCode, "description", desc)
		return createErrMsg
	}
	ec.Logger.Info("modify Access Rule succeeded.", "name", arReq.Name)
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

func (appService AppService) EnableService(ec *EaaClient) error {
	ec.Logger.Info("EnableService")
	if appService.UUIDURL == "" {
		ec.Logger.Error("enabling access service failed. empty uuid_url")
		return ErrEnableService
	}
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, SERVICES_URL, appService.UUIDURL)

	getResp, err := ec.SendAPIRequest(apiURL, "PUT", &appService, nil, false)
	if err != nil {
		return fmt.Errorf("failed to enable app service: %w", err)
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(getResp)
		appServiceErrMsg := fmt.Errorf("%w: %s", ErrEnableService, desc)
		return appServiceErrMsg
	}
	return nil
}

func (appService AppService) CreateAppServiceStruct(ec *EaaClient) ([]interface{}, error) {
	if appService.UUIDURL == "" {
		ec.Logger.Error("CreateAppServiceStruct failed. empty uuid_url")
		return nil, fmt.Errorf("creating appservice struct failed. empty uuid_url")
	}

	response, err := GetAccessControlRules(ec, appService.UUIDURL)
	if err != nil {
		ec.Logger.Error("get access control rules failed", "error", err)
		return nil, err
	}

	if len(response.ACLRules) == 0 {
		ec.Logger.Error("no ACL rules found in response", "error", err)
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

func GetACLService(ec *EaaClient, appUUIDURL string) (*AppService, error) {
	ec.Logger.Info("GetACLService")
	if appUUIDURL == "" {
		ec.Logger.Error("get access service failed. empty uuid_url")
		return nil, ErrEnableService
	}
	apiURL := fmt.Sprintf("%s://%s/%s/%s/services", URL_SCHEME, ec.Host, APPS_URL, appUUIDURL)
	asResponse := AppServicesResponse{}

	getResp, err := ec.SendAPIRequest(apiURL, "GET", nil, &asResponse, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get app services: %w", err)
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(getResp)
		appServiceErrMsg := fmt.Errorf("%w: %s", ErrAppServicesGet, desc)
		return nil, appServiceErrMsg
	}

	for _, ac := range asResponse.AppServices {
		if ac.Service.ServiceType == SERVICE_TYPE_ACCESS_CTRL {
			return &ac.Service, nil
		}
	}

	return nil, ErrAppServicesGet
}

func ExtractACLService(ctx context.Context, d *schema.ResourceData, ec *EaaClient) (*ACLService, error) {
	var aclAccessRules []AccessRule
	var aclSrv ACLService

	// Read services list from ResourceData
	servicesRaw, ok := d.Get("service").([]interface{})
	if !ok {
		ec.Logger.Info("invalid service configuration")
		return nil, fmt.Errorf("invalid service configuration")
	}

	// Iterate through each service
	for _, svcRaw := range servicesRaw {
		appSvc, ok := svcRaw.(map[string]interface{})
		if !ok {
			ec.Logger.Info("invalid service configuration.")
			return nil, fmt.Errorf("invalid service configuration")
		}

		serviceType, ok := appSvc["service_type"].(string)
		if !ok {
			ec.Logger.Info("invalid or missing service_type.")
			return nil, fmt.Errorf("invalid or missing service_type")
		}

		if serviceType != string(ServiceTypeAccessCtrl) {
			continue
		}

		serviceStatus, ok := appSvc["status"].(string)
		if !ok {
			ec.Logger.Info("Invalid or missing service status.")
			return nil, fmt.Errorf("invalid or missing service status")
		}
		aclSrv.Status = serviceStatus

		// Extract access rules
		accessRulesRaw, ok := appSvc["access_rule"].([]interface{})
		if !ok {
			ec.Logger.Info("invalid access_rule list")
			return nil, fmt.Errorf("invalid access_rule list")
		}

		for _, accessRuleRaw := range accessRulesRaw {
			accessRule, ok := accessRuleRaw.(map[string]interface{})
			if !ok {
				ec.Logger.Info("invalid access_rule configuration.")
				return nil, fmt.Errorf("invalid access_rule configuration")
			}

			var rules []ACLSetting
			rulesRaw, ok := accessRule["rule"].([]interface{})
			if !ok {
				ec.Logger.Info("Invalid rule list type.")
				return nil, fmt.Errorf("invalid rule list")
			}

			for _, ruleRaw := range rulesRaw {
				ruleMap, ruleMapOK := ruleRaw.(map[string]interface{})
				if !ruleMapOK {
					ec.Logger.Info("invalid rule configuration.")
					return nil, fmt.Errorf("invalid rule configuration")
				}

				ruleOperator, ruleOperatorOK := ruleMap["operator"].(string)
				if !ruleOperatorOK {
					ec.Logger.Info("Invalid or missing rule operator.")
					return nil, fmt.Errorf("invalid or missing rule operator")
				}

				ruleType, ruleTypeOK := ruleMap["type"].(string)
				if !ruleTypeOK {
					ec.Logger.Info("Invalid or missing rule type.")
					return nil, fmt.Errorf("invalid or missing rule type")
				}

				value, valueOK := ruleMap["value"].(string)
				if !valueOK {
					ec.Logger.Info("invalid or missing rule value.")
					return nil, fmt.Errorf("invalid or missing rule value")
				}
				rule := ACLSetting{
					Operator: ruleOperator,
					Type:     ruleType,
					Value:    value,
				}

				if err := rule.Validate(); err != nil {
					return nil, fmt.Errorf("invalid rule configuration")
				}

				rules = append(rules, rule)
			}

			name, ok := accessRule["name"].(string)
			if !ok {
				ec.Logger.Info("Invalid or missing access_rule name.")
				return nil, fmt.Errorf("invalid or missing access_rule name")
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

func GetAccessControlRules(ec *EaaClient, serviceUUIDURL string) (*ACLRulesResponse, error) {
	ec.Logger.Info("GetAccessControlRules")
	if serviceUUIDURL == "" {
		ec.Logger.Error("get access control rules failed. empty uuid_url")
		return nil, ErrEnableService
	}
	apiURL := fmt.Sprintf("%s://%s/%s/%s/rules", URL_SCHEME, ec.Host, SERVICES_URL, serviceUUIDURL)
	asResponse := ACLRulesResponse{}

	getResp, err := ec.SendAPIRequest(apiURL, "GET", nil, &asResponse, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get access control rules: %w", err)
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(getResp)
		appServiceErrMsg := fmt.Errorf("%w: %s", ErrAppServicesGet, desc)
		return nil, appServiceErrMsg
	}

	return &asResponse, nil
}
