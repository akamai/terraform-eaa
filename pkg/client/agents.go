package client

import (
	"context"
	"fmt"
	"net/http"

	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type ConnAdvancedSettings struct {
	NetworkInfo []string `json:"network_info,omitempty"`
}

type CreateConnectorRequest struct {
	Description           *string              `json:"description"`
	Name                  string               `json:"name"`
	AdvancedSettings      ConnAdvancedSettings `json:"advanced_settings"`
	Status                int                  `json:"status"`
	Package               int                  `json:"package"`
	AuthService           bool                 `json:"auth_service"`
	DataService           bool                 `json:"data_service"`
	DebugChannelPermitted bool                 `json:"debug_channel_permitted"`
}

type Connector struct {
	IPAddr                *string              `json:"ip_addr,omitempty"`
	OSVersion             *string              `json:"os_version,omitempty"`
	PublicIP              *string              `json:"public_ip,omitempty"`
	DiskSize              *string              `json:"disk_size,omitempty"`
	RAMSize               *string              `json:"ram_size,omitempty"`
	Timezone              *string              `json:"tz,omitempty"`
	Subnet                *string              `json:"subnet,omitempty"`
	AgentVersion          *string              `json:"agent_version,omitempty"`
	CPU                   *string              `json:"cpu,omitempty"`
	ConnectorPool         *ConnectorPool       `json:"connector_pool,omitempty"`
	Region                *string              `json:"region,omitempty"`
	DownloadURL           *string              `json:"download_url,omitempty"`
	ActivationCode        *string              `json:"activation_code,omitempty"`
	MAC                   *string              `json:"mac,omitempty"`
	Description           *string              `json:"description,omitempty"`
	Gateway               *string              `json:"gateway,omitempty"`
	GeoLocation           *string              `json:"geo_location,omitempty"`
	Hostname              *string              `json:"hostname,omitempty"`
	PrivateIP             *string              `json:"private_ip,omitempty"`
	LastCheckin           *string              `json:"last_checkin,omitempty"`
	LoadStatus            *string              `json:"load_status,omitempty"`
	DHCP                  string               `json:"dhcp,omitempty"`
	Name                  string               `json:"name,omitempty"`
	UUID                  string               `json:"uuid,omitempty"`
	UUIDURL               string               `json:"uuid_url,omitempty"`
	Policy                string               `json:"policy,omitempty"`
	AdvancedSettings      ConnAdvancedSettings `json:"advanced_settings"`
	Reach                 int                  `json:"reach,omitempty"`
	UnificationStatus     int                  `json:"unification_status,omitempty"`
	AgentInfraType        int                  `json:"agent_infra_type,omitempty"`
	AgentType             int                  `json:"agent_type,omitempty"`
	Package               int                  `json:"package,omitempty"`
	State                 int                  `json:"state,omitempty"`
	Status                int                  `json:"status,omitempty"`
	UpDirCount            int                  `json:"up_dir_count,omitempty"`
	UpAppsCount           int                  `json:"up_apps_count,omitempty"`
	DebugChannelPermitted bool                 `json:"debug_channel_permitted,omitempty"`
	AgentUpgradeEnabled   bool                 `json:"agent_upgrade_enabled,omitempty"`
	AgentUpgradeSuspended bool                 `json:"agent_upgrade_suspended,omitempty"`
	DataService           bool                 `json:"data_service,omitempty"`
	ManualOverride        bool                 `json:"manual_override,omitempty"`
	OSUpgradesUpToDate    bool                 `json:"os_upgrades_up_to_date,omitempty"`
}

func (ccr *CreateConnectorRequest) CreateConnectorRequestFromSchema(ctx context.Context, d *schema.ResourceData, ec *EaaClient) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnector, logging.TagValidate}
	logging.Info(ctx, "validating connector request from schema", tags)

	// validate and set the name field
	name, ok := d.GetOk("name")
	if !ok {
		logging.Warn(ctx, "create Connector failed. 'name' is required but missing", tags)
		return logging.Errorf(tags, "'name' is required but missing")
	}
	nameStr, ok := name.(string)
	if !ok || nameStr == "" {
		logging.Warn(ctx, "create Connector failed. 'name' must be a non-empty string", tags)
		return logging.Errorf(tags, "'name' must be a non-empty string")
	}
	ccr.Name = nameStr

	// set the description field if present
	if description, hasDescription := d.GetOk("description"); hasDescription {
		descriptionStr, descriptionOK := description.(string)
		if descriptionOK && descriptionStr != "" {
			ccr.Description = &descriptionStr
		}
	}

	// set the debug_channel_permitted field with default value if not present
	if debugPermitted, hasDebugPermitted := d.GetOk("debug_channel_permitted"); hasDebugPermitted {
		debugChPermitted, debugPermittedOK := debugPermitted.(bool)
		if debugPermittedOK {
			ccr.DebugChannelPermitted = debugChPermitted
		} else {
			logging.Warn(ctx, "create Connector failed. 'debug_channel_permitted' must be a boolean", tags)
			return logging.Errorf(tags, "'debug_channel_permitted' must be a boolean")
		}
	} else {
		logging.Info(ctx, "debug_channel_permitted is not present, defaulting to false", tags)
		ccr.DebugChannelPermitted = false
	}

	// validate and set the package field
	connPackage, ok := d.GetOk("package")
	if !ok {
		logging.Warn(ctx, "create Connector failed. 'package' is required but missing", tags)
		return logging.Errorf(tags, "'package' is required but missing")
	}
	connPackageStr, ok := connPackage.(string)
	if !ok {
		logging.Warn(ctx, "create Connector failed. 'package' must be a string", tags)
		return logging.Errorf(tags, "'package' must be a string")
	}
	atype := ConnPackageType(connPackageStr)
	value, err := atype.ToInt()
	if err != nil {
		logging.Warn(ctx, "create Connector failed. 'package' is invalid", tags, map[string]any{"error": err})
		return logging.Wrapf(err, tags, "'package' value is invalid")
	}
	ccr.Package = value

	// handle advanced_settings if present
	if advSettingsData, ok := d.GetOk("advanced_settings"); ok {
		advSettingsList, ok := advSettingsData.([]interface{})
		if ok && len(advSettingsList) > 0 {
			if advSettingsData, ok := advSettingsList[0].(map[string]interface{}); ok {
				advSettings := ConnAdvancedSettings{}
				if networkInfoData, ok := advSettingsData["network_info"]; ok {
					networkInfoList, ok := networkInfoData.([]interface{})
					if ok {
						for _, networkInfo := range networkInfoList {
							if ip, ok := networkInfo.(string); ok {
								advSettings.NetworkInfo = append(advSettings.NetworkInfo, ip)
							}
						}
					}
				}

				// assign default value if 'Network_Info' is empty
				if len(advSettings.NetworkInfo) == 0 {
					advSettings.NetworkInfo = []string{"0.0.0.0/0"}
				}

				ccr.AdvancedSettings = advSettings
			}
		}
	}

	// set default 'AdvancedSettings' if not populated
	if ccr.AdvancedSettings.NetworkInfo == nil {
		ccr.AdvancedSettings = ConnAdvancedSettings{
			NetworkInfo: []string{"0.0.0.0/0"},
		}
	}

	// Set additional fields
	ccr.Status = STATE_ENABLED
	ccr.AuthService = true
	ccr.DataService = true

	logging.Info(ctx, "connector request validation succeeded", tags, map[string]any{"name": ccr.Name})
	return nil
}

func (cur *Connector) UpdateConnector(ctx context.Context, d *schema.ResourceData, ec *EaaClient) (*Connector, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnector, logging.TagUpdate}
	logging.Info(ctx, "update connector starting", tags, map[string]any{"uuid": cur.UUIDURL})

	createRequest := CreateConnectorRequest{}
	err := createRequest.CreateConnectorRequestFromSchema(ctx, d, ec)
	if err != nil {
		logging.Warn(ctx, "create connector request from schema failed", tags, map[string]any{"error": err.Error()})
		return nil, err
	}
	cur.Name = createRequest.Name
	cur.Description = createRequest.Description
	cur.AdvancedSettings = createRequest.AdvancedSettings
	cur.DebugChannelPermitted = createRequest.DebugChannelPermitted
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, AGENTS_URL, cur.UUIDURL)

	var connResp Connector
	updateConnResp, err := ec.SendAPIRequest(ctx, apiURL, "PUT", cur, &connResp, false)
	if err != nil {
		logging.Warn(ctx, "update connector API request failed", tags, map[string]any{"error": err.Error()})
		return nil, logging.Wrapf(err, tags, "update connector API request failed")
	}

	if updateConnResp.StatusCode != http.StatusOK {
		desc := FormatErrorDescription(updateConnResp)
		logging.Warn(ctx, "update connector failed", tags, map[string]any{"status": updateConnResp.StatusCode, "description": desc})
		return nil, logging.Errorf(tags, "update connector failed: %s", desc)
	}

	logging.Info(ctx, "update connector succeeded", tags, map[string]any{"name": cur.Name})
	return &connResp, nil
}

func (ccr *CreateConnectorRequest) CreateConnector(ctx context.Context, ec *EaaClient) (*Connector, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnector, logging.TagCreate}
	logging.Info(ctx, "create connector starting", tags, map[string]any{"name": ccr.Name})

	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, AGENTS_URL)

	var connResp Connector
	createConnResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", ccr, &connResp, false)
	if err != nil {
		logging.Warn(ctx, "create connector API request failed", tags, map[string]any{"error": err.Error()})
		return nil, logging.Wrapf(err, tags, "create connector API request failed")
	}

	if createConnResp.StatusCode != http.StatusOK {
		desc := FormatErrorDescription(createConnResp)
		logging.Warn(ctx, "create connector failed", tags, map[string]any{"status": createConnResp.StatusCode, "description": desc})
		return nil, logging.Errorf(tags, "create connector failed: %s", desc)
	}

	logging.Info(ctx, "create connector succeeded", tags, map[string]any{"name": ccr.Name})
	return &connResp, nil
}

type ConnectorResponse struct {
	Connectors []Connector `json:"objects,omitempty"`
	Meta       struct {
		Next       *string `json:"next,omitempty"`
		Previous   *string `json:"previous,omitempty"`
		Limit      int     `json:"limit,omitempty"`
		Offset     int     `json:"offset,omitempty"`
		TotalCount int     `json:"total_count,omitempty"`
	} `json:"meta,omitempty"`
}

func GetAgents(ctx context.Context, ec *EaaClient) ([]Connector, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagAgent, logging.TagList}
	logging.Info(ctx, "get agents starting", tags)

	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, AGENTS_URL)
	agentsResponse := ConnectorResponse{}

	getResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &agentsResponse, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "get agents API request failed")
	}

	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(getResp)
		return nil, logging.Errorf(tags, "get agents failed: %s", desc)
	}

	var agents []Connector
	for i := range agentsResponse.Connectors {
		conn := &agentsResponse.Connectors[i]
		if conn.Name == "" || conn.UUIDURL == "" {
			continue
		}
		agents = append(agents, *conn)
	}

	logging.Info(ctx, "get agents succeeded", tags, map[string]any{"count": len(agents)})
	return agents, nil
}

func GetAgentUUIDs(ctx context.Context, ec *EaaClient, agentNames []string) ([]string, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagAgent, logging.TagRead}
	logging.Info(ctx, "get agent UUIDs starting", tags, map[string]any{"agent_names": agentNames})

	agents, err := GetAgents(ctx, ec)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "failed to get agents")
	}

	agentUUIDs := make([]string, 0)
	for _, agentName := range agentNames {
		found := false
		for i := range agents {
			if agentName == agents[i].Name {
				agentUUIDs = append(agentUUIDs, agents[i].UUIDURL)
				found = true
				break
			}
		}
		if !found {
			return nil, logging.Errorf(tags, "agent not found: %s", agentName)
		}
	}

	logging.Info(ctx, "get agent UUIDs succeeded", tags, map[string]any{"count": len(agentUUIDs)})
	return agentUUIDs, nil
}

func DeleteConnector(ctx context.Context, ec *EaaClient, connUUIDURL string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagConnector, logging.TagDelete}
	logging.Info(ctx, "delete connector starting", tags, map[string]any{"uuid": connUUIDURL})

	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, AGENTS_URL, connUUIDURL)

	deleteResp, err := ec.SendAPIRequest(ctx, apiURL, http.MethodDelete, nil, nil, false)
	if err != nil {
		return logging.Wrapf(err, tags, "delete connector API request failed")
	}

	if deleteResp.StatusCode < http.StatusOK || deleteResp.StatusCode >= http.StatusMultipleChoices {
		return logging.Errorf(tags, "delete connector failed with status %d", deleteResp.StatusCode)
	}

	logging.Info(ctx, "delete connector succeeded", tags, map[string]any{"uuid": connUUIDURL})
	return nil
}
